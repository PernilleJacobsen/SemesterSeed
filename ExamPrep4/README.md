# SemesterSeed
MeanPeriod4
1 - Explain basic security terms like 

authentication, confirming identy of a client usually by log-in procedure......

authorization, determine whether you are allowed to use the service or perform an operation

confidentiality, protect data from disclosure to unauthorized persons
integrity, maintain data consistency

SSL/TLS . TLS - the green chainlock in the browser:
SSL: Secure Socket Layer is predecessor to TLS and is the standard security technology for establishing an encrypted link 
between a web server and a browser. This link ensures that all data passed between the web server and browsers remain 
private and integral. To be able to create an SSL connection a web server requires an SSL Certificate. When you 
choose to activate SSL on your web server your web server then creates two cryptographic keys - a Private Key and a 
Public Key.

The Public Key does not need to be secret and is placed into a Certificate Signing Request (CSR) - a data file 
also containing your details. During the SSL Certificate application process, the Certification Authority will 
4validate your details and issue an SSL Certificate containing your details and allowing you to use SSL. 
Your web server will match your issued SSL Certificate to your Private Key. Your web server will then be able 
to establish an encrypted link between the website and your customer's web browser.

The complexities of the SSL protocol remain invisible to your customers. Instead their browsers provide them 
with a key indicator to let them know they are currently protected by an SSL encrypted session - the lock icon 
in the lower right-hand corner, clicking on the lock icon displays your SSL Certificate and the details about it. 
All SSL Certificates are issued to either companies or legally accountable individuals.

Typically an SSL Certificate will contain your domain name, your company name, your address, your city, your state
and your country. It will also contain the expiration date of the Certificate and details of the Certification 
Authority responsible for the issuance of the Certificate. When a browser connects to a secure site it will 
retrieve the site's SSL Certificate and check that it has not expired, it has been issued by a Certification 
Authority the browser trusts, and that it is being used by the website for which it has been issued. If it fails 
on any one of these checks the browser will display a warning to the end user letting them know that the site is 
not secured by SSL.


examples - see semesterseed.

2 - Explain basic security threads like: Cross Site Scripting (XSS), SQL Injection and whether something similar to SQL injection is possible with NoSQL databases like MongoDB and DOS-attacks. 

XSS: XSS enables attackers to inject client-side scripts into web pages viewed by other users..... 

SQL injection

DOS attacks: Denial-of-service - is an attemp to make a machine or network ressource unavailable or interrupt/suspend 
a service. Typical it is a attack performed by thousands of IP adresses working together and requesting a service 
at the same time - and by that blocks the service.

3 - Explain, at a fundamental level, the technologies involved, and the steps required initialize a SSL connection 
    between a browser and a server and how to use SSL in a secure way. 

•	A browser requests a secure page (usually https://).

•	The web server sends its public key with its certificate.

•	The browser checks that the certificate was issued by a trusted party (usually a trusted root CA), that the 
  certificate is still valid and that the certificate is related to the site contacted.

•	The browser then uses the public key, to encrypt a random symmetric encryption key and sends it to the server 
  with the encrypted URL required as well as other encrypted http data.
•	The web server decrypts the symmetric encryption key using its private key and uses the symmetric key 
  to decrypt the URL and http data.
•	The web server sends back the requested html document and http data encrypted with the symmetric key.
•	The browser decrypts the http data and html document using the symmetric key and displays the information.

4 - Explain and demonstrate ways to protect user passwords on our backends, and why this is necessary. 

Use a seperate database to store passwords, always use salt and hashing instead of plaintext storing. 

Necessary because evil people will try to get the passwords to do bad things.
Bcrypt to secure the userpassword...from semesterseed models/user:
UserSchema.pre('save', function (next) {
    var user = this;
    if (this.isModified('password') || this.isNew) {
        bcryptjs.genSalt(10, function (err, salt) {
            if (err) {
                return next(err);
            }
            bcryptjs.hash(user.password, salt, function (err, hash) {
                if (err) {
                    return next(err);
                }
                user.password = hash;
                next();
            });
        });
    } else {
        return next();
    }
});


5 - Explain about password hashing, salts and the difference between bcrypt and older (not recommended) 
  algorithms like sha1, md5 etc. 
  
Hashing passwords are one the first important rules of security instead of storing in plain text the pasword 
is being hashed to at new value. This value is almost impossible to know unless you know the password that 
are hashed.....rainbow tables can breake them by knowing millions and millions of hashed passwords and 
just trying them out one by one.

If you salt it mean to add a salt to the password and then hash it together.

Bcrypt incoorperates a salt and work very slow - designet to be slow to prevent rainbow table attacks....
the more is thrown at it - the slower it gets
Bcrypt uses Blowfish to encrypt a magic string, using a key "derived" from the password. Later, when a user 
enters a password, the key is derived again, and if the ciphertext produced by encrypting with that key matches 
the stored ciphertext, the user is authenticated. The ciphertext is stored in the "password" table, but the 
derived key is never stored.






