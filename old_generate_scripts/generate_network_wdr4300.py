#!/usr/bin/env python3

import sys

USAGE = "Usage: %s num_wlans@2.4ghz [num_vlans@5ghz]" % sys.argv[0]
network_filename = "network"
wireless_filename = "wireless"

base_network_text = """
config interface 'loopback'
	option ifname 'lo'
	option proto 'static'
	option ipaddr '127.0.0.1'
	option netmask '255.0.0.0'

config globals 'globals'
	option ula_prefix 'fd78:c2e2:d583::/48'

config interface 'lan'
	option ifname 'eth0.1'
	option force_link '1'
	option type 'bridge'
	option proto 'static'
	option ipaddr '192.168.1.1'
	option netmask '255.255.255.0'
	option ip6assign '60'

config interface 'wan'
	option ifname 'eth0.2'
	option proto 'dhcp'

config interface 'wan6'
	option ifname 'eth0.2'
	option proto 'dhcpv6'

config switch
	option name 'switch0'
	option reset '1'
	option enable_vlan '1'

config switch_vlan
	option device 'switch0'
	option vlan '1'
	option ports '0t 2 3 4 5'

config switch_vlan
	option device 'switch0'
	option vlan '2'
	option ports '0t 1'
"""

#config_network_text = """
#config interface 'wlan{0}'
#	option proto 'static'
#	option ipaddr '10.0.{0}.1'
#	option netmask '255.255.255.0'
#	option gateway '10.0.{0}.1'
#	option broadcast '10.0.{0}.255'
#	option type 'bridge'
#"""

wireless_header = """
config wifi-device 'radio0'
	option type 'mac80211'
	option channel '11'
	option hwmode '11g'
	option path 'platform/ar934x_wmac'
	option htmode 'HT20'
	option disabled '0'
	option txpower '8'
	option country 'US'

config wifi-device 'radio1'
	option type 'mac80211'
	option channel '36'
	option hwmode '11a'
	option path 'pci0000:00/0000:00:00.0'
	option htmode 'HT20'
	option disabled '0'
	option txpower '8'
	option country 'US'
"""

config_wireless_text = """
config wifi-iface
	option device 'radio{1}'
	option network 'lan'
	option mode 'ap'
	option ssid 'TEST NETWORK {1}{0} DO NOT USE'
	option encryption 'psk2'
	option key 'testtes{0}'
"""



def main():
  # check args
  try:
    num_nets = int(sys.argv[1])
  except:
    print(USAGE)
    sys.exit(-1)
  try:
    num_nets2 = int(sys.argv[2])
  except:
    num_nets2 = 0

  with open(network_filename, "w") as f:
    f.write(base_network_text)
    #for i in range(num_nets):
    #  f.write(config_network_text.format(i))

  with open(wireless_filename, "w") as f:
    f.write(wireless_header)
    for i in range(num_nets):
      f.write(config_wireless_text.format(i,0))
    for i in range(num_nets2):
      f.write(config_wireless_text.format(i,1))


if __name__ == "__main__":
  main()
