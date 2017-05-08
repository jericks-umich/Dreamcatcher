package universityofmichigan.dreamcatcher;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;

public class MainActivity extends AppCompatActivity {

    public static boolean serverIsRunning = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        /**
         * Right here is where you should do the initial authentication with the router and get the cookie
         */

        SharedPreferences sharedPrefs = getApplication().getSharedPreferences(String.valueOf(R.string.app_save_file), Context.MODE_PRIVATE);
        if(!(sharedPrefs.contains(String.valueOf(R.string.app_username)) && sharedPrefs.contains(String.valueOf(R.string.app_pw)))){
            login();
        }
        else{
            Log.d("Main Activity: ", "Credentials are saved!");
            ((GlobalClass) getApplicationContext()).setHaveSavedCredentials(true,
                    sharedPrefs.getString(String.valueOf(R.string.app_username), "None"),
                    sharedPrefs.getString(String.valueOf(R.string.app_pw), "None"));
        }
       // if(!((GlobalClass) getApplicationContext()).getServerRunning()) {
            serverIsRunning = true;
            startServer();
       // }
    }

    /**
     * This function will launch the login screen
     */
    private void login(){
        Intent loginIntent = new Intent(this, LoginActivity.class);
        startActivity(loginIntent);
    }

    /**
     * This function will create an intent for the Server Service and start the service.
     */
    private void startServer(){
        // declare the service
        Intent serviceIntent = new Intent(this, ServerService.class);
        // start the service --> will run onHandleIntent() in ServerService class
        startService(serviceIntent);
    }
}
