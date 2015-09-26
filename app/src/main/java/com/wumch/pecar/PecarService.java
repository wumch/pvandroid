package com.wumch.pecar;

import android.app.Notification;
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

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;


public class PecarService extends VpnService implements Handler.Callback, Runnable
{
    private final int authTimeout = 60000;

    private Crypto crypto;

    private String serverAddress;
    private String serverPort;
    private byte[] username, password;
    private PendingIntent configIntent;

    private Handler handler;
    private Thread thread;

    private SocketChannel upstream;
    private ParcelFileDescriptor ifd;

    public class ResCode
    {
        public static final int OK = 0;
        public static final int NONEXISTS = 1;
        public static final int EXPIRED = 2;
        public static final int TRAFFIC_EXHAUST = 3;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId)
    {
        // The handler is only used to show messages.
        if (handler == null) {
            handler = new Handler(this);
        }

        // Stop the previous session by interrupting the thread.
        if (thread != null) {
            thread.interrupt();
        }

        // Extract information from the intent.
        String prefix = getPackageName();
        serverAddress = intent.getStringExtra(prefix + ".ADDRESS");
        serverPort = intent.getStringExtra(prefix + ".PORT");
        username = intent.getStringExtra(prefix + ".USERNAME").getBytes();
        password = intent.getStringExtra(prefix + ".PASSWORD").getBytes();

        fillDefaultParam();

        thread = new Thread(this, "ToyVpnThread");
        thread.start();
        foregroundStart();
        return START_STICKY;
    }

    private void fillDefaultParam()
    {
        if (serverAddress.isEmpty()) {
            serverAddress = "192.168.1.9";
        }
        if (serverPort.isEmpty()) {
            serverPort = "1723";
        }
        if (username.length == 0) {
            username = "wumch".getBytes();
        }
        if (password.length == 0) {
            password = "test".getBytes();
        }
    }

    private void foregroundStart()
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
    public void onDestroy()
    {
        if (thread != null) {
            thread.interrupt();
        }
    }

    @Override
    public boolean handleMessage(Message message)
    {
        if (message != null) {
            Toast.makeText(this, message.what, Toast.LENGTH_SHORT).show();
        }
        return true;
    }

    @Override
    public synchronized void run()
    {
        try {
            InetSocketAddress server = new InetSocketAddress(serverAddress, Integer.parseInt(serverPort));
            Log.i(getText(R.string.log_tag).toString(), "server: [" + serverAddress + ":" + Integer.toString(Integer.parseInt(serverPort)) + "]");
            handler.sendEmptyMessage(R.string.connecting);
            run(server);
            Log.i(getText(R.string.log_tag).toString(), "Giving up");
        } catch (Exception e) {
            Log.e(getText(R.string.log_tag).toString(), "runserver(server) got " + e.toString());
        } finally {
            try {
                ifd.close();
            } catch (IOException e) {
                // ignore
            } finally {
                ifd = null;
                handler.sendEmptyMessage(R.string.disconnected);
                Log.i(getText(R.string.log_tag).toString(), "Exiting");
            }
        }
    }

    private boolean run(InetSocketAddress server)
    {
        crypto = new Crypto(getText(R.string.log_tag).toString());
        boolean connected = false;
        try {
            if (prepareTunnel(server)) {
                connected = true;
                handler.sendEmptyMessage(R.string.connected);
                configure();
                work();
            } else {
                connected = false;
            }
        } catch (IOException e) {
            // TODO: maybe network error, notify user.
            Log.e(getText(R.string.log_tag).toString(), "IO exception: " + e.toString());
        } catch (Exception e) {
            Log.e(getText(R.string.log_tag).toString(), "exception: " + e.toString());
        } finally {
            try {
                if (upstream.isOpen()) {
                    upstream.close();
                }
                ifd.close();
            } catch (IOException e) {
                // ignore
            }
        }
        return connected;
    }

    private boolean prepareTunnel(InetSocketAddress serverAddr) throws IOException
    {
        upstream = SocketChannel.open();
        if (!protect(upstream.socket())) {
            throw new IllegalStateException("Cannot protect the upstream");
        }
        upstream.connect(serverAddr);
        upstream.configureBlocking(false);
        try {
            return handshake();
        } catch (Exception e) {
            Log.i(getText(R.string.log_tag).toString(), "exception from handshake" );
            return false;
        }
    }

    private boolean work() throws IOException, ShortBufferException, BadPaddingException, IllegalBlockSizeException, InterruptedException
    {
        FileInputStream dsr = new FileInputStream(ifd.getFileDescriptor());
        FileOutputStream dsw = new FileOutputStream(ifd.getFileDescriptor());

        byte[] dr = new byte[32767];
        byte[] dw = new byte[32767];
        byte[] ur = new byte[32767];
        byte[] uw = new byte[32767];

        while (true) {
            int len = dsr.read(dr);
            if (len > 0) {
                crypto.encrypt(dr, len, uw);
                int written = upstream.write(ByteBuffer.wrap(uw, 0, len));
                Log.i(getText(R.string.log_tag).toString(), "upstream written: " + Integer.toString(written));
            }

            len = upstream.read(ByteBuffer.wrap(ur, 0, ur.length));
            if (len > 0) {
                crypto.decrypt(ur, len, dw);
                dsw.write(dw, 0, len);
            }
            Thread.sleep(50);
        }
    }

    private boolean handshake() throws Exception
    {
        ByteBuffer packet = ByteBuffer.allocate(128);
        packet.position(crypto.genKeyIvList(packet.array()));
        Log.i(getText(R.string.log_tag).toString(), "position: " + Integer.toString(packet.position()));
        packet.put((byte)username.length);
        packet.put((byte)password.length);
        packet.put(username);
        packet.put(password);
        packet.flip();
        int written = upstream.write(packet);
        Log.i(getText(R.string.log_tag).toString(), "written: " + Integer.toString(written));

        packet.clear();
        final int interval = 100;
        for (int i = 0, end = (int)Math.ceil(authTimeout / interval); i < end; ++i) {
            Thread.sleep(interval);
            packet.limit(1);
            int len = upstream.read(packet);
            if (len > 0) {
                packet.position(0);
                int authRes = packet.get(0) & 0xff;
                Log.i(getText(R.string.log_tag).toString(), "authRes: " + authRes + ", Rescode.OK: " + ResCode.OK);
                if (authRes == 0) {
                    Log.i(getText(R.string.log_tag).toString(), "authRes == 0" );
                    return true;
                } else if (authRes == 1) {
                    Log.i(getText(R.string.log_tag).toString(), "authRes == 1" );
                    return false;
                } else if (authRes == 2) {
                    Log.i(getText(R.string.log_tag).toString(), "authRes == 2" );
                    return false;
                } else if (authRes == 3) {
                    Log.i(getText(R.string.log_tag).toString(), "authRes == 3" );
                    return false;
                } else {
                    Log.i(getText(R.string.log_tag).toString(), "authRes == else" );
                    return true;
                }
            }
        }
        Log.i(getText(R.string.log_tag).toString(), "authRes != any" );
        throw new IllegalStateException("Timed out");
    }

    private void configure()
    {
        Builder builder = new Builder();
        builder.setMtu(1400)
            .setSession(getText(R.string.app).toString())
            .setConfigureIntent(configIntent)
            .addRoute("0.0.0.0", 0)
            .addAddress("10.0.0.2", 32);
        if (ifd.getFd() >= 0) {
            try {
                ifd.close();
            } catch (Exception e) {
                // ignore
            }
        }
        ifd = builder.establish();
    }
}
