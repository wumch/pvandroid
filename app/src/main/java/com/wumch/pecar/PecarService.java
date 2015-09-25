package com.wumch.pecar;

import android.app.Notification;
import android.content.Context;
import android.content.Intent;
import android.app.PendingIntent;
import android.net.VpnService;
import android.os.Handler;
import android.os.Message;
import android.os.ParcelFileDescriptor;
import android.support.v4.app.NotificationCompat;
import android.util.Log;
import android.widget.Toast;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.*;


public class PecarService extends VpnService implements Handler.Callback, Runnable
{
    private static final String TAG = "PecarService";
    private static final int ONGOING_NOTIFICATION = 1;

    private final int authTimeout = 60000;

    private final Crypto crypto = new Crypto(getApplicationContext());

    private String mServerAddress;
    private String mServerPort;
    private byte[] username, password;
    private byte[] mSharedSecret;
    private PendingIntent mConfigureIntent;

    private Handler mHandler;
    private Thread mThread;

    private SocketChannel tunnel;
    private ParcelFileDescriptor mInterface;
    private String mParameters;

    public class ResCode
    {
        public static final byte OK = 0,
            NONEXISTS = 1,
            EXPIRED = 2,
            TRAFFIC_EXHAUST = 3;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // The handler is only used to show messages.
        if (mHandler == null) {
            mHandler = new Handler(this);
        }

        // Stop the previous session by interrupting the thread.
        if (mThread != null) {
            mThread.interrupt();
        }

        // Extract information from the intent.
        String prefix = getPackageName();
        mServerAddress = intent.getStringExtra(prefix + ".ADDRESS");
        mServerPort = intent.getStringExtra(prefix + ".PORT");
        String sharedSecret = intent.getStringExtra(prefix + ".SECRET");
        mSharedSecret = sharedSecret.getBytes();
        username = intent.getStringExtra(prefix + ".USERNAME").getBytes();
        password = intent.getStringExtra(prefix + ".PASSWORD").getBytes();

        fillDefaultParam();

        Log.i(TAG, "secret:[" + new String(mSharedSecret) + "]");

        // Start a new session by creating a new thread.
        mThread = new Thread(this, "ToyVpnThread");
        mThread.start();
        start();
        return START_STICKY;
    }

    private void fillDefaultParam()
    {
        if (mServerAddress.isEmpty()) {
            mServerAddress = "192.168.1.9";
        }
        if (mServerPort.isEmpty()) {
            mServerPort = "1723";
        }
        if (mSharedSecret.length == 0) {
            mSharedSecret = "test".getBytes();
        }
        if (username.length == 0) {
            username = "wumch".getBytes();
        }
        if (password.length == 0) {
            password = "test".getBytes();
        }
    }

    private void start()
    {
        Intent notificationIntent = new Intent(this, PecarClient.class);
        notificationIntent.setFlags(Notification.FLAG_ONGOING_EVENT);
        PendingIntent pendingIntent = PendingIntent.getActivity(this, 0, notificationIntent, 0);
        NotificationCompat.Builder builder = new NotificationCompat.Builder(this)
            .setContentIntent(pendingIntent)
            .setSmallIcon(R.drawable.icon)
            .setContentTitle(getText(R.string.notification_title))
            .setContentText(getText(R.string.notification_content))
            .setOngoing(true);
        Notification notification = builder.build();
        startForeground(R.drawable.r1x, notification);
    }

    @Override
    public void onDestroy() {
        if (mThread != null) {
            mThread.interrupt();
        }
    }

    @Override
    public boolean handleMessage(Message message) {
        if (message != null) {
            Toast.makeText(this, message.what, Toast.LENGTH_SHORT).show();
        }
        return true;
    }

    @Override
    public synchronized void run() {
        try {
            Log.i(TAG, "Starting");

            // If anything needs to be obtained using the network, get it now.
            // This greatly reduces the complexity of seamless handover, which
            // tries to recreate the tunnel without shutting down everything.
            // In this demo, all we need to know is the server address.
            InetSocketAddress server = new InetSocketAddress(
                    mServerAddress, Integer.parseInt(mServerPort));
            Log.i(TAG, "server: [" + mServerAddress + ":" + Integer.toString(Integer.parseInt(mServerPort)) + "]");

            // We try to create the tunnel for several times. The better way
            // is to work with ConnectivityManager, such as trying only when
            // the network is avaiable. Here we just use a counter to keep
            // things simple.
            for (int attempt = 0; attempt < 10; ++attempt) {
                mHandler.sendEmptyMessage(R.string.connecting);

                // Reset the counter if we were connected.
                if (run(server)) {
                    attempt = 0;
                }

                // Sleep for a while. This also checks if we got interrupted.
                Thread.sleep(3000);
            }
            Log.i(TAG, "Giving up");
        } catch (Exception e) {
            Log.e(TAG, "Got " + e.toString());
        } finally {
            try {
                mInterface.close();
            } catch (Exception e) {
                // ignore
            }
            mInterface = null;
            mParameters = null;

            mHandler.sendEmptyMessage(R.string.disconnected);
            Log.i(TAG, "Exiting");
        }
    }

    private boolean run(InetSocketAddress server)
    {
        boolean connected = true;
        try {
            if (prepareTunnel(server)) {
                mHandler.sendEmptyMessage(R.string.connected);
                work();
            } else {
                connected = false;
            }
        } catch (IOException e) {
            // TODO: notify user.
            Log.e(TAG, "Got " + e.toString());
        } finally {
            try {
                if (tunnel.isOpen()) {
                    tunnel.close();
                }
                mInterface.close();
            } catch (IOException e) {
                // ignore
            }
        }
        return connected;
    }

    private boolean prepareTunnel(InetSocketAddress serverAddr) throws IOException
    {
        tunnel = SocketChannel.open();
        if (!protect(tunnel.socket())) {
            throw new IllegalStateException("Cannot protect the tunnel");
        }
        tunnel.connect(serverAddr);
        tunnel.configureBlocking(false);
        try {
            return handshake(tunnel);
        } catch (Exception e) {
            return false;
        }
    }

    private boolean work() throws IOException
    {
        // Packets to be sent are queued in this input stream.
        FileInputStream in = new FileInputStream(mInterface.getFileDescriptor());

        // Packets received need to be written to this output stream.
        FileOutputStream out = new FileOutputStream(mInterface.getFileDescriptor());

        // Allocate the buffer for a single packet.
        ByteBuffer packet = ByteBuffer.allocate(32767);

        // We use a timer to determine the status of the tunnel. It
        // works on both sides. A positive value means sending, and
        // any other means receiving. We start with receiving.
        int timer = 0;

        // We keep forwarding packets till something goes wrong.
        while (true) {
            // Assume that we did not make any progress in this iteration.
            boolean idle = true;

            // Read the outgoing packet from the input stream.
            int length = in.read(packet.array());
            if (length > 0) {
                // Write the outgoing packet to the tunnel.
                packet.limit(length);
                tunnel.write(packet);
                packet.clear();

                // There might be more outgoing packets.
                idle = false;

                // If we were receiving, switch to sending.
                if (timer < 1) {
                    timer = 1;
                }
            }

            // Read the incoming packet from the tunnel.
            length = tunnel.read(packet);
            if (length > 0) {
                // Ignore control messages, which start with zero.
                if (packet.get(0) != 0) {
                    // Write the incoming packet to the output stream.
                    out.write(packet.array(), 0, length);
                }
                packet.clear();

                // There might be more incoming packets.
                idle = false;

                // If we were sending, switch to receiving.
                if (timer > 0) {
                    timer = 0;
                }
            }

            // If we are idle or waiting for the network, sleep for a
            // fraction of time to avoid busy looping.
            if (idle) {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    // ignore
                }

                // Increase the timer. This is inaccurate but good enough,
                // since everything is operated in non-blocking mode.
                timer += (timer > 0) ? 100 : -100;

                // We are receiving for a long time but not sending.
                if (timer < -15000) {
                    // Send empty control messages.
                    packet.put((byte) 0).limit(1);
                    for (int i = 0; i < 3; ++i) {
                        packet.position(0);
                        tunnel.write(packet);
                    }
                    packet.clear();

                    // Switch to sending.
                    timer = 1;
                }

                // We are sending for a long time but not receiving.
                if (timer > 20000) {
                    throw new IllegalStateException("Timed out");
                }
            }
        }
    }

    private boolean handshake(SocketChannel tunnel) throws Exception
    {
        byte[] keyIvChunk = new byte[512];
        int filled = crypto.genKeyIvList(keyIvChunk);

        ByteBuffer packet = ByteBuffer.allocate(1024);
        packet.put(keyIvChunk, 0, filled);
        packet.putChar((char)username.length);
        packet.put(username);
        packet.putChar((char)password.length);
        packet.put(password);

        tunnel.write(packet);
        packet.clear();
        packet.limit(1);

        final int interval = 100;
        for (int i = 0, end = (int)Math.ceil(authTimeout / interval); i < end; ++i) {
            Thread.sleep(interval);
            if (tunnel.read(packet) > 0) {
                switch (packet.get(0))
                {
                    case ResCode.OK:
                        return true;
                    case ResCode.NONEXISTS:
                        break;
                    case ResCode.EXPIRED:
                        break;
                    case ResCode.TRAFFIC_EXHAUST:
                        break;
                    default:
                        break;
                }
                return false;
            }
        }
        throw new IllegalStateException("Timed out");
    }

    private void configure(String parameters) throws Exception {
        // If the old interface has exactly the same parameters, use it!
        if (mInterface != null && parameters.equals(mParameters)) {
            Log.i(TAG, "Using the previous interface");
            return;
        }

        // Configure a builder while parsing the parameters.
        Builder builder = new Builder();
        for (String parameter : parameters.split(" ")) {
            String[] fields = parameter.split(",");
            try {
                switch (fields[0].charAt(0)) {
                    case 'm':
                        builder.setMtu(Short.parseShort(fields[1]));
                        Log.i(TAG, "mtu: [" + Integer.toString(Short.parseShort(fields[1])) + "]");
                        break;
                    case 'a':
                        builder.addAddress(fields[1], Integer.parseInt(fields[2]));
                        Log.i(TAG, "addr: [" + fields[1] + "/" + Integer.toString(Integer.parseInt(fields[2])) + "]");
                        break;
                    case 'r':
                        builder.addRoute(fields[1], Integer.parseInt(fields[2]));
                        Log.i(TAG, "route:[" + fields[1] + "/" + Integer.toString(Integer.parseInt(fields[2])) + "]");
                        break;
                    case 'd':
                        builder.addDnsServer(fields[1]);
                        Log.i(TAG,  "dns:[" + fields[1] + "]");
                        break;
                    case 's':
                        builder.addSearchDomain(fields[1]);
                        Log.i(TAG, "search: [" + fields[1] + "]");
                        break;
                }
            } catch (Exception e) {
                throw new IllegalArgumentException("Bad parameter: " + parameter);
            }
        }

        // Close the old interface since the parameters have been changed.
        try {
            mInterface.close();
        } catch (Exception e) {
            // ignore
        }

        // Create a new interface using the builder and save the parameters.
        mInterface = builder.setSession(mServerAddress)
                .setConfigureIntent(mConfigureIntent)
                .establish();
        mParameters = parameters;
        Log.i(TAG, "New interface: " + parameters);
    }
}
