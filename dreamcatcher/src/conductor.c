#include <conductor.h>

void* conduct(void* arg) {
  // TODO: 
  // Loop
    // Poll the config file for changes
      // If config file changes, for each change, send client a new message through GCM
    // Listen to Google Cloud Messaging service for updates
      // If GCM sends status update, update config file
    // sleep for ~ 5 seconds?

  //rule r;
  //pop_rule_from_queue(&r);
}

