Google Apps Password Sync for Samba4
===========

Reads from your Samba4 AD and updates passwords in Google Apps 
Note that this solution requires you to enable "password hash userPassword schemes = CryptSHA256 CryptSHA512" in smb.conf

Install notes
===========
1. add params "password hash userPassword schemes = CryptSHA256 CryptSHA512" in smb.conf
2. restart samba
3. Change the password of a user to synchronize (changing the password will be mandatory for all users in order to feed the new hashes)
4. apt-get install python3-pip git
5. cd /tmp
6. git clone https://github.com/sfonteneau/samba4-gaps.git
7. mv samba4-gaps /opt/samba4-gaps
8. cd /opt/samba4-gaps
9. pip3 install -r requirements.txt
10. mkdir /etc/gaps
11. cp -f gaps.conf.template /etc/gaps/gaps.conf
12. cp -f service.json.template /etc/gaps/service.json
13. Configure /etc/gaps/gaps.conf
14. Create a project in Google API Console and add Admin SDK permission (read/write)
15. Create a JSON Config for your project in Google Developer Console (Service accounts, addkey, json)
16. Install the JSON config to your samba machine in /etc/gaps/service.json 
17. cd /opt/samba4-gaps
18. python3 gaps.py

log visible in syslog

* If you are having issues with Google Permissions - you might need to add domain-wide authority to your service
  Delegate domain-wide authority to your service account https://developers.google.com/drive/web/delegation#delegate_domain-wide_authority_to_your_service_account

