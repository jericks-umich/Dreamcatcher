package universityofmichigan.dreamcatcher;

import android.app.Application;

/**
 * Created by roblevy on 4/2/17.
 */

public class GlobalClass extends Application {
    /**
     * boolean to keep track of when the server is running and when it is not running
     */
    private static boolean serverIsRunning = false;

    /**
     * boolean to keep track of whether the user has saved his credentials yet
     */
    private static boolean haveSavedCredentials = false;

    /**
     * username for the user --> gets set during login
     */
    private static String username;

    /**
     * password for the user --> gets set during login
     */
    private static String password;

    /**
     * hash for cookie authentication
     */
    private static String sys_auth;

    /**
     * boolean to let us know if cookie is saved
     */
    private static boolean hasCookie = false;

    /**
     * router ip address
     */
    private static final String router = "http://192.168.1.1/cgi-bin/luci/";

    private static final String host = "192.168.1.1";

    private static final String appRulesUrl = "http://192.168.1.1/cgi-bin/luci/admin/security/rule/rules_1";

    public boolean getServerRunning(){
        return serverIsRunning;
    }

    public String getUsername(){
        return username;
    }

    public String getPassword(){
        return password;
    }

    public String getRouterURL(){
        return router;
    }

    public void setServerRunning(boolean in){
        serverIsRunning = in;
    }

    public String getHost(){ return host; }

    public String getAppRulesUrl(){ return appRulesUrl; }

    public String getCookie(){
        return sys_auth;
    }

    public Boolean isCookieSaved(){
        return hasCookie;
    }

    /**
     * This function will set the user credentials the first time you sign in.
     * @param in
     * @param user_in
     * @param pass_in
     */
    public void setHaveSavedCredentials(boolean in, String user_in, String pass_in){
        haveSavedCredentials = in;
        username = user_in;
        password = pass_in;
    }

    public void setCookie(String sys_auth_in){
        sys_auth = sys_auth_in;
        hasCookie = true;
    }


}
