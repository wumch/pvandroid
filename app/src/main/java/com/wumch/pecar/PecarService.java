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
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

public class PecarService extends VpnService implements Handler.Callback, Runnable
{
    private final int authTimeout = 60000;
    private final int workInterval = 5;
    private final int workIntervalMax = 10000;
    private final int idleInterval = 10000;
    private final int ipPackMinLen = 20;

    private String serverAddress;
    private String serverPort;
    private byte[] username, password;
    private InetSocketAddress serverAddr;
    private Builder ifdBuilder;

    private Crypto crypto;
    private Handler handler;
    private Thread thread;

    private SocketChannel upstream;
    private ParcelFileDescriptor ifd;
    private FileInputStream dsr;
    private FileOutputStream dsw;

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
        serverAddr = new InetSocketAddress(serverAddress, Integer.parseInt(serverPort));

        thread = new Thread(this, "PecarThread");
        thread.start();
        foregroundStart();
        return START_STICKY;
    }

    private void fillDefaultParam()
    {
        if (serverAddress.isEmpty()) {
            serverAddress = "192.168.88.157";
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
        crypto = new Crypto(getText(R.string.log_tag).toString());  // Crypto is order sensitive.
        try {
            Log.i(getText(R.string.log_tag).toString(), "server: [" + serverAddress + ":" + Integer.toString(Integer.parseInt(serverPort)) + "]");
            handler.sendEmptyMessage(R.string.connecting);
            doRun();
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

    private void doRun()
    {
        try {
            if (prepareUpstream()) {
                handler.sendEmptyMessage(R.string.connected);
                prepareIfdBuilder();
                prepareIfd();
                work();
            }
        } catch (IOException e) {
            // TODO: maybe network error, notify user.
            Log.e(getText(R.string.log_tag).toString(), "IO exception doRun()->catch(IOException): " + e.toString());
        } catch (Exception e) {
            Log.e(getText(R.string.log_tag).toString(), "exception doRun()->catch(Exception): " + e.toString());
            e.printStackTrace();
        } finally {
            try {
                if (upstream.isOpen()) {
                    upstream.close();
                }
                ifd.close();
            } catch (IOException e) {
                Log.e(getText(R.string.log_tag).toString(), "exception doRun()->finally->catch(IOException): " + e.toString());
            }
        }
    }

    private boolean work() throws IOException, ShortBufferException, BadPaddingException, IllegalBlockSizeException, InterruptedException
    {
        dsr = new FileInputStream(ifd.getFileDescriptor());
        dsw = new FileOutputStream(ifd.getFileDescriptor());

        ByteBuffer bufdr = ByteBuffer.allocate(65535);
        ByteBuffer bufdw = ByteBuffer.allocate(65535);
        ByteBuffer bufur = ByteBuffer.allocate(65535);
        ByteBuffer bufuw = ByteBuffer.allocate(65535);

        int turn = 0;
        int continuedInactive = 0;
        boolean inactive, isFirstInactive = true;
        int continuedIdle = 0;
        long lastActive = System.currentTimeMillis();
        while (true) {
            inactive = true;
            int len = dsr.read(bufdr.array());
            if (len > 0) {
                inactive = false;
                bufdr.limit(len);
                crypto.encrypt(bufdr, len, bufuw);
                bufuw.flip();
                try {
                    upstream.write(bufuw);
                } catch (SocketException e) {
                    Log.i(getText(R.string.log_tag).toString(), "re-prepareUpstream: wrok()->try->catch(SocketException)-1: [" + e.getClass().getName() + "]" + e.getMessage());
                    prepareUpstream();
                } catch (IOException e) {
                    Log.i(getText(R.string.log_tag).toString(), "wrok()->try->catch(IOException)-1: [" + e.getClass().getName() + "]" + e.getMessage());
                }
                bufdr.clear();
                bufuw.clear();
            }

            len = upstream.read(bufur);
            if (len > 0) {
                inactive = false;
                ++turn;
                try {
                    bufur.flip();
                    crypto.decrypt(bufur, len, bufdw);
                    bufur.clear();
                    final int totalBytes = bufdw.position();
                    if (totalBytes >= ipPackMinLen)
                    {
                        int packLen = bufdw.getShort(2) & 0xffff;
                        if (packLen == totalBytes)
                        {
                            dsw.write(bufdw.array(), 0, totalBytes);
                        }
                        else if (packLen < totalBytes)
                        {
                            bufdw.flip();
                            while (dsWritePack(bufdw, bufur.array())) {}  // reuse bufur as cache
                            bufur.limit(bufur.capacity() - (bufdw.limit() - bufdw.position()));
                            leftAlignBuffer(bufdw);
                        }
                        else
                        {
                            bufur.limit(bufur.capacity() - totalBytes);
                        }
                    }
                    else
                    {
                        bufur.limit(bufur.capacity() - totalBytes);
                    }
                } catch (IOException e) {
                    Thread.sleep(10);
                    try {
                        dsw.write(bufur.array(), 0, len);
                    } catch (IOException e1) {
                        Log.i(getText(R.string.log_tag).toString(), "fd(" + ifd.getFd() + ") turn(" + turn + ") re-prepareIfd: wrok()->try->catch(IOException)-2: [" + e.getClass().getName() + "]" + e.getMessage());
                    }
                    if (!ifd.getFileDescriptor().valid()) {
                        Log.i(getText(R.string.log_tag).toString(), "fd(" + ifd.getFd() + ") turn(" + turn + ") " + "first byte: " + (int)bufdr.array()[0] +  "re-prepareIfd: wrok()->try->catch(IOException)-2: [" + e.getClass().getName() + "]" + e.getMessage());
                        prepareIfd();
                    }
                    Log.i(getText(R.string.log_tag).toString(), "fd(" + ifd.getFd() + ") turn(" + turn + ") wrok()->try->catch(IOException)-2: [" + e.getClass().getName() + "]" + e.getMessage());
                }
            }
/*
            if (inactive)
            {
                if (++continuedInactive > 10)
                {
                    continuedInactive = 0;
                    if (System.currentTimeMillis() - lastActive > idleInterval)
                    {
                        ++continuedIdle;
                    }
                    Thread.sleep(Math.min(++continuedIdle * workInterval, workIntervalMax));
                }
                else
                {
                    if (isFirstInactive)
                    {
                        isFirstInactive = false;
                        lastActive = System.currentTimeMillis();
                    }
                    Thread.sleep(0);
                }
            }
            else
            {
                continuedInactive = 0;
                continuedIdle = 0;
                isFirstInactive = true;
            }
        // */
        }
    }

    private boolean dsWritePack(ByteBuffer data, byte[] cache) throws IOException
    {
        int packLen = data.getShort(data.position() + 2) & 0xffff;
        int bytesRemain = data.limit() - data.position();
        if (bytesRemain < packLen)
        {
            return false;
        }
        else
        {
            data.get(cache, 0, packLen);
            dsw.write(cache, 0, packLen);
            return bytesRemain - packLen >= ipPackMinLen;
        }
    }

    private void leftAlignBuffer(ByteBuffer buffer)
    {
        int bytesRemain = buffer.limit() - buffer.position();
        if (bytesRemain > 0)
        {
            if (bytesRemain <= buffer.position())
            {
                System.arraycopy(buffer.array(), buffer.position(), buffer.array(), 0, bytesRemain);
            }
            else
            {
                for (int step = buffer.position(), src = buffer.position(), dest = 0, remainBytes = bytesRemain;
                     remainBytes > 0;
                     remainBytes -= step, src += step, dest += step)
                {
                    System.arraycopy(buffer.array(), src, buffer.array(), dest, step);
                }
            }
        }
        buffer.clear();
        buffer.position(bytesRemain);
    }

    private boolean handshake() throws Exception
    {
        ByteBuffer packet = ByteBuffer.allocate(128);
        packet.position(crypto.genKeyIvList(packet.array()));
        packet.put((byte)username.length);
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
                        " destroy()->try->catch(Exception): " + e.getMessage());
            }
        }
    }

    private PendingIntent getConfigIntent()
    {
        // make the prepareIfdBuilder Button show the Log
        Intent intent = new Intent(getBaseContext(), PecarClient.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
        PendingIntent startLW = PendingIntent.getActivity(this, 0, intent, 0);
        intent.addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
        return startLW;

    }

    private boolean prepareUpstream() throws IOException
    {
        if (upstream != null && upstream.isConnected()) {
            upstream.close();
        }
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

    private void prepareIfd()
    {
        Log.i(getText(R.string.log_tag).toString(), "allocate fd");
        ifd = ifdBuilder.establish();
    }

    private void prepareIfdBuilder()
    {
        ifdBuilder = new Builder()
            .setMtu(1400)
            .setSession(getText(R.string.app).toString())
            .setConfigureIntent(getConfigIntent())
            .addRoute("0.0.0.0", 0)
            .addAddress("10.0.0.2", 32);
    }
}
