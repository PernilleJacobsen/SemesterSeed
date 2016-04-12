/**
 * Created by Pernille on 10-04-2016.
 */
module.exports.jwtConfig = {
    secret: "MyDogIsNice",
    tokenExpirationTime: 60 * 20, //seconds
    audience: "yoursite.net",
    issuer: "yourcompany@somewhere.com"
}
