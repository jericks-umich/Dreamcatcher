package universityofmichigan.dreamcatcher;

import android.app.IntentService;
import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.support.v4.app.NotificationCompat;
import android.text.format.Formatter;
import android.util.Log;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

/**
 * Created by roblevy on 3/27/17.
 */


public class ServerService extends IntentService {

    static final String interfaceForConnection = "wlan0";

    public ServerService(){
        super("ServerService Launched!");
    }

    /**
     * TODO: Find a way to get the IP address to bind to from the current network interface
     */
    @Override
    protected void onHandleIntent(Intent workIntent) {
        // Gets data from the incoming Intent
        //String dataString = workIntent.getDataString();

        // Note: We will not use the passed in Intent in our application
        // define the port we want to use
        final int port = 6000;
        try {
            Log.d("Checkpoint:", "We made it into onHandleIntent");

            // use a connectivity manager to get the current network IP
            WifiManager connManager = (WifiManager) getApplicationContext().getSystemService(Context.WIFI_SERVICE);
            WifiInfo wifiInfo = connManager.getConnectionInfo();
            int ipAddress = wifiInfo.getIpAddress();
            // this line handles the endianess of the system and avoids the IP address being backwards
            ipAddress = (ByteOrder.nativeOrder().equals(ByteOrder.LITTLE_ENDIAN)) ?
                    Integer.reverseBytes(ipAddress) : ipAddress;
            byte[] ipArray = BigInteger.valueOf(ipAddress).toByteArray();
            InetAddress myInetIp = InetAddress.getByAddress(ipArray);
            String ip = myInetIp.getHostAddress();
            Log.d("WIFI IP: ", ip);
            // using ServerSocket class means we don't need to call bind
            ServerSocket serverSocket = new ServerSocket(port, 2, myInetIp);
            while(true){
                Log.d("Checkpoint:", "Server created, accepting connections");
                Log.d("Server Address: ", String.valueOf(serverSocket.getLocalSocketAddress()));
                Log.d("Server Port: ", String.valueOf(serverSocket.getLocalPort()));
                Log.d("Is Server Closed:", String.valueOf(serverSocket.isClosed()));
                Log.d("IS Server Bound: ", String.valueOf(serverSocket.isBound()));
                Log.d("Network interface: ", String.valueOf(NetworkInterface.getByInetAddress(InetAddress.getByName("172.22.84.158"))));

                // the ServerSocket class treats each incoming request as its own Socket
                Socket incomingConnection = serverSocket.accept();
                Log.d("Checkpoint:", "Connection ACCEPTED!");
                // handle the incoming connection
                handleConnection(incomingConnection);
                // close the connection
                incomingConnection.close();
            }
        } catch (IOException e) {
            Log.d("Error:", "These was a problem opening the socket on port " + String.valueOf(port));
            e.printStackTrace();
        }

    }

    /**
     * This function will receive incoming connections and handle the data they carry.
     * @param connection
     */
    private void handleConnection(Socket connection) throws IOException {
        // In this function --> start by creating a basic notification below:
        /**
         * TODO: Receive the data
         */
        InputStream dataStream = connection.getInputStream();
        String totalData = org.apache.commons.io.IOUtils.toString(dataStream, "UTF-8");
        Log.d("Handling Error:", totalData);
        /*if(totalData.length() != 161){
            Log.d("Handling Error:", totalData);
        }*/
        String id = totalData.substring(0, 32);
        String message = totalData.substring(32);
        Log.d("ID: ", id);
        Log.d("Message", message);
        // pushing the notification will bring you to the main page of the application
        Intent intent = new Intent(this, MainActivity.class);
        // I am using System.currentTimeMillis() to give each notification a unique id
        PendingIntent pendingIntent = PendingIntent.getActivity(this, (int)
                System.currentTimeMillis(), intent, 0);

        // get intent for the accept action
        Intent acceptIntent = new Intent(this, AcceptActivity.class);
        acceptIntent.putExtra("id", id);
        // get pending intent for the accept action
        PendingIntent pendingAccept = PendingIntent.getActivity(this,(int) System.currentTimeMillis() , acceptIntent, 0);

        // get intent for the deny action
        Intent denyIntent = new Intent(this, DenyActivity.class);
        denyIntent.putExtra("id", id);
        // get pending intent for the deny action
        PendingIntent pendingDeny = PendingIntent.getActivity(this,(int) System.currentTimeMillis() , denyIntent, 0);

        // build actions for this notification
        NotificationCompat.Action accept = new NotificationCompat.Action.Builder(R.drawable.notification_icon, "Accept",
                pendingAccept).build();
        NotificationCompat.Action deny = new NotificationCompat.Action.Builder(R.drawable.notification_icon,
                "Deny", pendingDeny).build();
        NotificationCompat.Action detailedView = new NotificationCompat.Action.Builder(R.drawable.notification_icon,
                "View Detailed", pendingIntent).build();

        /**
         * TODO: click notification and go to "View Detailed" by default
         */

        // build a notification
        Notification n = new NotificationCompat.Builder(this)
                .setContentTitle("DreamCatcher: A new rule has arrived")
                .setContentText(message)
                .setSmallIcon(R.drawable.notification_icon)
                .setContentIntent(pendingIntent)
                .addAction(accept)
                .addAction(deny)
                .addAction(detailedView).build();

        // get notification manager and trigger notification
        NotificationManager manager = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        manager.notify(0, n);
    }
}
