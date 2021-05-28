# verifiable-credential-java

## Get it
### Maven
Add the JitPack repository to build file

```xml
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>
```

Add dependency

```xml
<dependency>
    <groupId>com.github.METADIUM</groupId>
    <artifactId>verifiable-credential-java</artifactId>
    <version>0.2.1</version>
</dependency>
```
### Gradle
Add root build.gradle

```gradle
allprojects {
    repositories {
        maven { url 'https://jitpack.io' }
    }
}
```
Add dependency

```gradle
dependencies {
    implementation 'com.github.METADIUM:verifiable-credential-java:0.2.1'
}
```
If use Google service plug-in in android, add code

```gradle
googleServices {
    disableVersionCheck = true
}
```


## Use it

### Make Verifiable Credential
```java
VerifiableCredential vc = new VerifiableCredential();
vc.setId(URI.create("http://aa.metadium.com/credential/343"));  // Set id of verifiable credential
vc.addTypes(Collections.singletonList("NameCredential"));       // Add Credential type name
vc.setIssuer(URI.create("did:meta:0x3489384932859420"));        // Set did of issuer
vc.setIssuanceDate(issuedDate);                                 // Set issued date
vc.setExpirationDate(expireDate);                               // Set expire date

// Add credential subject
LinkedHashMap<String, String> subject = new LinkedHashMap<>();
subject.put("id", "did:meta:0x11111111120");
subject.put("name", "mansud");
vc.setCredentialSubject(subject);
```

### Sign VerifiableCredential
```java
SignedJWT signedVc = vc.sign(
    "did:meta:0x348938499420#managementKey#4358",   // key id of signer
    "0d8mf03",                                      // nonce
    new ECDSASigner(privateKey)
);
String signedVcString = signedVc.serialize();
```

### Verify VerifiableCredential
```java
SignedJWT signedVc = SignedJWT.parse(signedVcString);

// verifying
if (signedVc.verify(new ECDSAVerifier(publicKey))) {
	VerifiableCredential verifiedVc = new VerifiableCredential(signedVc);
	if (verifiedVc == null) {
		// invalid vc
		return;
	}
   // Get subject
   Map<String, Object> credentialSubject = (Map<String, Object>)verifiedVc.getCredentialSubject();
}
else {
	// not verified
}
```

### Make Verifiable Presentation
```java
VerifiablePresentation vp = new VerifiablePresentation();
vp.setId(URI.create("http://aa.metadium.com/presentation/343"));    // Set id of verifiable presentatil
vp.setHolder(URI.create("did:meta:0x3489384932859420"));            // Set did of holder
vp.addTypes(Collections.singletonList("TestPresentation"));         // Add presentation type name
vp.addVerifiableCredential(verifiableCredential_1);                 // Add signed verifiable credential
vp.addVerifiableCredential(verifiableCredential_2);
```

### Sign Verifiable Presentation
```java
SignedJWT signedVp = vp.sign(
    "did:meta:0x348938499420#managementKey#4358",   // key id of holder
    "0d8mf03",                                      // nonce
    new ECDSASigner(privateKey)
);
String signedVpString = jwsObject.serialize();
```

### Verify Verifiable Presentation
```java
SignedJWT signedVp = Signed.parse(signedVpString);

// Verify verifiable presentation
if (signedVp.verify(new ECDSAVerifier(publicKey))) {
	VerifiablePresentation verifiedVp = new VerifiablePresentation(signedVp);
	if (verifiedVp == null) {
		// invalid vp
		return;
	}
   // Get verifiable credential
   for (Object vc : verifiedVp.getVerifiableCredentials()) {
       VerifiableCredential = (String)vc;
   }
}
```
