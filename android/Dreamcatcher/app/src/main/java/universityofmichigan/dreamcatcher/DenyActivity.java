package universityofmichigan.dreamcatcher;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Log;
import android.view.View;

import com.android.volley.AuthFailureError;
import com.android.volley.NetworkError;
import com.android.volley.NetworkResponse;
import com.android.volley.NoConnectionError;
import com.android.volley.ParseError;
import com.android.volley.Request;
import com.android.volley.RequestQueue;
import com.android.volley.Response;
import com.android.volley.ServerError;
import com.android.volley.TimeoutError;
import com.android.volley.VolleyError;
import com.android.volley.toolbox.HurlStack;
import com.android.volley.toolbox.StringRequest;
import com.android.volley.toolbox.Volley;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

public class DenyActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        //setContentView(R.layout.activity_accept);

        /*
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        FloatingActionButton fab = (FloatingActionButton) findViewById(R.id.fab);
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Snackbar.make(view, "Replace with your own action", Snackbar.LENGTH_LONG)
                        .setAction("Action", null).show();
            }
        });
        */

        // get login info
        SharedPreferences sharedPrefs = getApplication().getSharedPreferences(
                String.valueOf(R.string.app_save_file), Context.MODE_PRIVATE);
        final String username = sharedPrefs.getString(String.valueOf(R.string.app_username), "NULL");
        final String password = sharedPrefs.getString(String.valueOf(R.string.app_pw), "NULL");

        RequestQueue requestQueue = Volley.newRequestQueue(getApplicationContext(), new HurlStack(){
            @Override
            protected HttpURLConnection createConnection(URL url) throws IOException {
                HttpURLConnection connection = super.createConnection(url);
                connection.setInstanceFollowRedirects(false);

                return connection;
            }
        });

        /**
         * Explanation: This was terribly tricky. We se up a custom Request Stack above in order
         * to disable the android default behavior of following 301/302 responses automatically.
         * Then, we trick the StringRequest class into processing the precieved 302 error response
         * in a way in which it would normally only parse a non-error response, in order to extract
         * the cookie and save it to the system. There is no reason to send the GET request, as unlike
         * the web application we are not displaying the web page, so after we extract the cookie
         * we can end this connection.
         */
        StringRequest postRequest = new StringRequest(Request.Method.POST,
                ((GlobalClass) getApplicationContext()).getRouterURL(),
                new Response.Listener<String>()
                {
                    // cookie param is called sysauth
                    @Override
                    public void onResponse(String response) {
                        // response
                        Log.d("Login Received: ", response);

                    }
                },
                new Response.ErrorListener()
                {
                    @Override
                    public void onErrorResponse(VolleyError error) {
                        // error
                        if(error instanceof TimeoutError){
                            Log.d("Shit: ","Timeout!!!!!!");
                        }
                        else if(error instanceof NoConnectionError){
                            Log.d("Shit: ","No Connection");
                        }
                        else if (error instanceof AuthFailureError) {
                            Log.d("Shit: ","Auth Error");
                        } else if (error instanceof ServerError) {
                            Log.d("Shit: ","Server Error");
                        } else if (error instanceof NetworkError) {
                            Log.d("Shit: ","Network Error");
                        } else if (error instanceof ParseError) {
                            Log.d("Shit: ","Parse Error");
                        }
                        else{
                            Log.d("Error.Response", getString(error.networkResponse.statusCode));
                        }

                    }
                }
        ) {
            @Override
            protected Map<String, String> getParams()
            {
                // TODO: change the parameters
                Log.d("GET PARAMS: ", "RUNNING");
                Map<String, String>  params = new HashMap<String, String>();
                params.put("luci_username", username);
                params.put("luci_password", password);

                return params;
            }
            @Override
            public Map<String, String> getHeaders() {
                Log.d("LOCALE: ","GET HEADERS RUNNING");
                HashMap<String, String> headers = new HashMap<String, String>();
                headers.put("Host", "192.168.1.1");
                // headers.put("User-Agent", );
                headers.put("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
                headers.put("Accept-Language", "en-US,en;q=0.5");
                headers.put("Referer", "http://192.168.1.1/cgi-bin/luci/");
                headers.put("Upgrade-Insecure-Requests", "1");
                headers.put("Connection", "keep-alive");
                headers.put("Content-Type", "application/x-www-form-urlencoded");
                return headers;
            }
            @Override
            protected VolleyError parseNetworkError(VolleyError volleyError){
                Log.d("IN HERE!!!", "YEEEE");
                //VolleyError error = new VolleyError(new String(volleyError.networkResponse.data));

                final int status = volleyError.networkResponse.statusCode;
                if(HttpURLConnection.HTTP_MOVED_PERM == status || status == HttpURLConnection.HTTP_MOVED_TEMP || status == HttpURLConnection.HTTP_SEE_OTHER) {
                    Log.d("WOOHOO! ", "I GOT THE REDIRECT!");
                    Map<String, String> headers = volleyError.networkResponse.headers;
                    Log.d("HEADER KEYS:", headers.toString());
                    String sysAuth = headers.get("Set-Cookie");
                    sysAuth = sysAuth.substring(8, 40);
                    Log.d("SYSAUTH: ", sysAuth);
                    ((GlobalClass) getApplicationContext()).setCookie(sysAuth);
                }
                else{
                    Log.d("Error: ", "Wrong Username/Password Combo");
                    Log.d("STATUS ", Integer.toString(status) );
                }
                return volleyError;
            }
        };

        requestQueue.add(postRequest);
        Log.d("REQUEST: ", postRequest.toString());
        //requestQueue.start();

        /**
         * TODO: Parse out and update the cookie
         */
        // *****************************************************
        try {
            Thread.sleep(500);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        // retrieve the identifier passed into the Intent
        Intent intent = getIntent();
        final String id = intent.getStringExtra("id");

        // craft and send post request to accept the rule
        StringRequest acceptRequest = new StringRequest(Request.Method.POST,
                ((GlobalClass) getApplicationContext()).getAppRulesUrl(),
                new Response.Listener<String>()
                {
                    // cookie param is called sysauth
                    @Override
                    public void onResponse(String response) {
                        // response
                        Log.d("onResponse:", "DENY WORKED");

                    }
                },
                new Response.ErrorListener()
                {
                    @Override
                    public void onErrorResponse(VolleyError error) {
                        // error
                        Log.d("Error.Response", error.networkResponse.toString());
                    }
                }
        ) {
            @Override
            protected Map<String, String> getParams()
            {
                // TODO: change the parameters
                Log.d("GET PARAMS: ", "RUNNING");
                Map<String, String>  params = new HashMap<String, String>();
                params.put("reject", id);

                return params;
            }
            @Override
            public Map<String, String> getHeaders() {
                Log.d("LOCALE: ","GET HEADERS RUNNING");
                HashMap<String, String> headers = new HashMap<String, String>();
                headers.put("Host", "192.168.1.1");
                headers.put("Accept", "application/json");
                headers.put("Accept-Language", "en-US,en;q=0.5");
                headers.put("Referer", "https://192.168.1.1/cgi-bin/luci/");
                headers.put("Cookie", "sysauth="+((GlobalClass) getApplicationContext()).getCookie());
                headers.put("Upgrade-Insecure-Requests", "1");
                headers.put("Connection", "keep-alive");
                headers.put("Content-Type", "application/x-www-form-urlencoded");
                return headers;
            }
            @Override
            protected Response<String> parseNetworkResponse(NetworkResponse response){
                Log.d("Network Response: ", "RUNNING");
                Map<String, String> headers =  response.headers;
                String rawCoookie = headers.get("Cookie");
                Log.d("COOKIE: ", rawCoookie);
                return super.parseNetworkResponse(response);
            }
        };
        requestQueue.add(acceptRequest);
        Log.d("REQUEST: ", acceptRequest.toString());

        Log.d("UPDATE","I HAVE COMPLETED REJECTING THE CONNECTION");
        //requestQueue.start();
        //requestQueue.start();
    }

}
