-   [Note]:
    - `wp` WordPress themes and plugins are written by the community and many vulnerabilities are improperly patched or are simply never fixed at all. This makes plugins and themes a great target for compromise.
- _WPScan_
    - WordPress vulnerability scanner
        - This tool attempts to determine the WordPress versions, themes, and plugins as well as their vulnerabilities.
    - WPScan looks up component vulnerabilities in the _WordPress Vulnerability Database_ which requires an API token. A limited API key can be obtained for free by registering an account on the WPScan homepage. However, even without providing an API key, WPScan is a great tool to enumerate WordPress instances.
    - To perform the scan without an API key, we'll provide the URL of the target for **--url**, set the plugin detection to aggressive, and specify to enumerate all popular plugins by entering **p** as an argument to **--enumerate**. In addition, we'll use **-o** to create an output file.
        - `wpscan --url http://192.168.50.244 --enumerate p --plugins-detection aggressive -o websrv1/wpscan`
        - `cat websrv1/wpscan`
    - WPScan discovered six active plugins in the target WordPress instance: _akismet classic-editor contact-form-7 duplicator elementor and wordpress-seo._ The output also states that the Duplicator plugin version is outdated.
- Use _searchsploit_ to find possible exploits for vulnerabilities in the installed plugins.
    
    - `searchsploit duplicator`

Summary:

- Let's summarize what information we obtained about WEBSRV1 in this section. We learned that the target machine is an Ubuntu 22.04 system with two open ports: 22 and 80. A WordPress instance runs on port 80 with various active plugins. A plugin named Duplicator is outdated and a SearchSploit query provided us with two vulnerability entries matching the version.