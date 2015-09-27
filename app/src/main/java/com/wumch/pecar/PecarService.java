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
    private final int workInterval = 50;

    private String serverAddress;
    private String serverPort;
    private byte[] username, password;

    private Crypto crypto;
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
        destroy();

        if (handler == null) {
            handler = new Handler(this);
        }
        String prefix = getPackageName();
        serverAddress = intent.getStringExtra(prefix + ".ADDRESS");
        serverPort = intent.getStringExtra(prefix + ".PORT");
        username = intent.getStringExtra(prefix + ".USERNAME").getBytes();
        password = intent.getStringExtra(prefix + ".PASSWORD").getBytes();
        fillDefaultParam();

        thread = new Thread(this, "PecarThread");
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
        destroy();
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
            Log.i(getText(R.string.log_tag).toString(), "run out");
        } catch (Exception e) {
            Log.e(getText(R.string.log_tag).toString(), "runserver(server) got " + e.toString());
        } finally {
            try {
                ifd.close();
            } catch (IOException e) {
                Log.i(getText(R.string.log_tag).toString(), "run()->finally->catch(IOException): " + e.getMessage());
            } finally {
                ifd = null;
                handler.sendEmptyMessage(R.string.disconnected);
                Log.i(getText(R.string.log_tag).toString(), "run()->finally->finanlly");
            }
        }
    }

    private void run(InetSocketAddress server)
    {
        crypto = new Crypto(getText(R.string.log_tag).toString());
        try {
            if (prepareUpstream(server)) {
                handler.sendEmptyMessage(R.string.connected);
                configure();
                work();
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
                Log.e(getText(R.string.log_tag).toString(), "exception (run(InetSocketAddress)->finally->catch(IOException)): " + e.toString());
            }
        }
    }

    private PendingIntent getConfigIntent()
    {
        // make the configure Button show the Log
        Intent intent = new Intent(getBaseContext(), PecarClient.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
        PendingIntent startLW = PendingIntent.getActivity(this, 0, intent, 0);
        intent.addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
        return startLW;

    }

    private boolean prepareUpstream(InetSocketAddress serverAddr) throws IOException
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
            Log.i(getText(R.string.log_tag).toString(), e.getClass().toString() +
                "prepareUpstream(InetSocketAddress)->try->catch(Exception): " + e.getMessage());
            return false;
        }
    }

    private boolean work() throws IOException, ShortBufferException, BadPaddingException, IllegalBlockSizeException, InterruptedException
    {
        FileInputStream dsr = new FileInputStream(ifd.getFileDescriptor());
        FileOutputStream dsw = new FileOutputStream(ifd.getFileDescriptor());

        byte[] dr = new byte[32767],
            dw = new byte[32767],
            ur = new byte[32767],
            uw = new byte[32767];

        while (true) {
            int len = dsr.read(dr);
            if (len > 0) {
                crypto.encrypt(dr, len, uw);
                int written = upstream.write(ByteBuffer.wrap(uw, 0, len));
                int written2 = upstream.write(ByteBuffer.wrap(uw, 0, len));     // TODO: test only
                int written3 = upstream.write(ByteBuffer.wrap(uw, 0, len));     // TODO: test only
                int written4 = upstream.write(ByteBuffer.wrap(uw, 0, len));     // TODO: test only
            }

            len = upstream.read(ByteBuffer.wrap(ur, 0, ur.length));
            if (len > 0) {
                crypto.decrypt(ur, len, dw);
                dsw.write(dw, 0, len);
            }
            Thread.sleep(workInterval);
        }
    }

    private boolean handshake() throws Exception
    {
        ByteBuffer packet = ByteBuffer.allocate(128);
        packet.position(crypto.genKeyIvList(packet.array()));
        packet.put((byte) username.length);
        packet.put((byte)password.length);
        packet.put(username);
        packet.put(password);
        packet.flip();
        upstream.write(packet);

        packet.clear();
        final int interval = 100;
        for (int i = 0, end = (int)Math.ceil(authTimeout / interval); i < end; ++i) {
            Thread.sleep(interval);
            packet.limit(1);
            if (upstream.read(packet) > 0) {
                packet.position(0);
                switch (packet.get(0))
                {
                case ResCode.OK:
                    return true;
                case ResCode.NONEXISTS:
                    return false;
                case ResCode.EXPIRED:
                    return false;
                case ResCode.TRAFFIC_EXHAUST:
                    return false;
                default:
                    return false;
                }
            }
        }
        throw new IllegalStateException("Timed out");
    }

    private void destroy()
    {
        // Stop the previous session by interrupting the thread.
        if (thread != null) {
            thread.interrupt();
            thread = null;
        }

        if (ifd != null && ifd.getFd() >= 0) {
            try {
                ifd.close();
            } catch (Exception e) {
                Log.i(getText(R.string.log_tag).toString(), e.getClass().toString() +
                        "configure()->try->catch(Exception): " + e.getMessage());
            }
        }
    }

    private void configure()
    {
        ifd = new Builder()
            .setMtu(1400)
            .setSession(getText(R.string.app).toString())
            .setConfigureIntent(getConfigIntent())
            .addRoute("0.0.0.0", 0)
            .addAddress("10.0.0.2", 32)
            .establish();
    }
}
