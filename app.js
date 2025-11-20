const express = require("express");
const saml = require("samlify");
const fs = require("fs");
const appUrl = "https://saml-sp-lbi2.onrender.com";

const app = express();
app.use(express.urlencoded({ extended: true }));

// ====== Service Provider (your SP) ======
const sp = saml.ServiceProvider({
    //  entityID: "http://localhost:3000/metadata",
    entityID: appUrl + "/metadata",
    assertionConsumerService: [{
        Binding: saml.Constants.namespace.post,
        Location: appUrl + "/assert"
    }],
    wantMessageSigned: true,   // important
    authnRequestsSigned: true,  // important
    wantAssertionsSigned: true,


    privateKey: fs.readFileSync("./key/sp.key").toString(),
    privateKeyPass: "",

    signatureConfig: {},

    // This adds the certificate into the metadata
    encPrivateKey: fs.readFileSync("./key/sp.key").toString(), // optional; safe to include
    signingCert: fs.readFileSync("./key/sp.crt").toString(),
    encryptionCert: fs.readFileSync("./key/sp.crt").toString(),

    signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
});



// ====== Identity Provider (external IdP) ======
const idpMetadata = fs.readFileSync("./idp-metadata.xml").toString();
const idp = saml.IdentityProvider({
    metadata: idpMetadata
});

// ====== SP METADATA ENDPOINT ======
app.get("/metadata", (req, res) => {
    res.type("application/xml");
    res.send(sp.getMetadata());
});

// ====== START LOGIN ======
app.get("/login", async (req, res) => {
    const { context } = await sp.createLoginRequest(idp, "redirect");
    res.redirect(context);
});

// ====== ACS ENDPOINT (SAML Response comes here) ======
app.post("/assert", async (req, res) => {
    console.log("Inside /assert");
    try {
        const response = await sp.parseLoginResponse(idp, "post", req);
        console.log("SAML Response:", response);

        res.send(`
      <h2>Login Successful</h2>
      <pre>${JSON.stringify(response.extract, null, 2)}</pre>
    `);
    } catch (err) {
        console.error(err);
        res.status(500).send("SAML Error: " + err.message);
    }
});

// ====== START SERVER ======
app.listen(80, () => console.log("SAML SP running on " + appUrl));
