package com.wumch.pecar;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;

public class PecarClient extends Activity implements View.OnClickListener
{
    private TextView username;
    private TextView password;
    private TextView serverAddress;
    private TextView serverPort;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_pecar);

        username = (TextView) findViewById(R.id.username);
        password = (TextView) findViewById(R.id.password);
        serverAddress = (TextView) findViewById(R.id.address);
        serverPort = (TextView) findViewById(R.id.port);

        findViewById(R.id.connect).setOnClickListener(this);
    }

    @Override
    public void onClick(View v) {
        Intent intent = VpnService.prepare(this);
        if (intent != null) {
            startActivityForResult(intent, 0);
        } else {
            onActivityResult(0, RESULT_OK, null);
        }
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data)
    {
        if (result == RESULT_OK) {
            String prefix = getPackageName();
            Intent intent = new Intent(this, PecarService.class)
                .putExtra(prefix + ".USERNAME", username.getText().toString())
                .putExtra(prefix + ".PASSWORD", password.getText().toString())
                .putExtra(prefix + ".ADDRESS", serverAddress.getText().toString())
                .putExtra(prefix + ".PORT", serverPort.getText().toString());
            startService(intent);
        }
    }
}