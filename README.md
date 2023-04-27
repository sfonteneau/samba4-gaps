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
5. git clone https://github.com/sfonteneau/samba4-gaps.git
6. mv samba4-gaps /opt/samba4-gaps
7. cd /opt/samba4-gaps
8. pip3 install -r requirements.txt
9. mkdir /etc/gaps
10. cp -f gaps.conf /etc/gaps/gaps.conf
11. Configure /etc/gaps/gaps.conf
12. Create a project in Google API Console and add Admin SDK permission (read/write)
13. Create a JSON Config for your project in Google Developer Console
14. Install the JSON config to your samba machine in /etc/gaps/service.json 
15. cd /opt/samba4-gaps
16. python3 gaps.py

* If you are having issues with Google Permissions - you might need to add domain-wide authority to your service
  Delegate domain-wide authority to your service account https://developers.google.com/drive/web/delegation#delegate_domain-wide_authority_to_your_service_account

