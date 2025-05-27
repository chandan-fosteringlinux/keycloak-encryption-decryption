
# Adding Encryption and Decryption in Keycloak

## Prerequisites

Ensure you have the following installed:

- JDK 21 (newer versions not supported)
- Git

```bash
java -version
git --version
```

Use the Maven wrapper (`./mvnw`) provided in the project root.

## Clone Keycloak Repository

```bash
git clone https://github.com/keycloak/keycloak.git
cd keycloak
```

## Modify the Login Template

### Backup Existing Template

```bash
mv themes/src/main/resources/theme/keycloak.v2/login/login.ftl themes/src/main/resources/theme/keycloak.v2/login/logincopy.ftl
```

### Edit the `login.ftl`

```bash
nano themes/src/main/resources/theme/keycloak.v2/login/login.ftl
```

Paste the following content into `login.ftl`:

```ftl
<#import "template.ftl" as layout>
<#import "field.ftl" as field>
<#import "buttons.ftl" as buttons>
<#import "social-providers.ftl" as identityProviders>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('username','password') displayInfo=realm.password && realm.registrationAllowed && !registrationDisabled??; section>
<!-- template: login.ftl -->

<#-- Header Section -->
<#if section = "header">
    ${msg("loginAccountTitle")}

<#-- Form Section -->
<#elseif section = "form">
    <div id="kc-form">
      <div id="kc-form-wrapper">
        <#if realm.password>
            <form id="kc-form-login" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post" novalidate="novalidate">
                <#if !usernameHidden??>
                    <#assign label>
                        <#if !realm.loginWithEmailAllowed>${msg("username")}<#elseif !realm.registrationEmailAsUsername>${msg("usernameOrEmail")}<#else>${msg("email")}</#if>
                    </#assign>
                    <@field.input name="username" label=label error=kcSanitize(messagesPerField.getFirstError('username','password'))?no_esc autofocus=true autocomplete="username" value=login.username!'' />
                    <@field.password name="password" label=msg("password") error="" forgotPassword=realm.resetPasswordAllowed autofocus=usernameHidden?? autocomplete="current-password">
                        <#if realm.rememberMe && !usernameHidden??>
                            <@field.checkbox name="rememberMe" label=msg("rememberMe") value=login.rememberMe?? />
                        </#if>
                    </@field.password>
                <#else>
                    <@field.password name="password" label=msg("password") forgotPassword=realm.resetPasswordAllowed autofocus=usernameHidden?? autocomplete="current-password">
                        <#if realm.rememberMe && !usernameHidden??>
                            <@field.checkbox name="rememberMe" label=msg("rememberMe") value=login.rememberMe?? />
                        </#if>
                    </@field.password>
                </#if>

                <input type="hidden" id="id-hidden-input" name="credentialId" <#if auth.selectedCredential?has_content>value="${auth.selectedCredential}"</#if>/>
                <@buttons.loginButton />
            </form>
        </#if>
      </div>
    </div>

<!-- Encryption Script -->
<script src="https://cdn.jsdelivr.net/npm/jsencrypt/bin/jsencrypt.min.js"></script>
<script>
document.getElementById('kc-form-login').addEventListener('submit', function(event) {
    event.preventDefault();
    const passwordField = document.querySelector('input[name="password"]');
    const usernameField = document.querySelector('input[name="username"]');
    const password = passwordField?.value || '';
    const username = usernameField?.value || '';

const publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6jb8C74RUUuKFCmerKOws
xhoH/9zyLE33J42rk5TjJmlM2FpFLACReEjpRCoYQ0qCg3PlY7woTffagV7sBVrsr
26JhQl1GpSuIHqD2p93pmBVdv6fQ5c0H9svU/4y9yZkxt/kHMtEPKZAd9ut+T2Emx
Cx6zaY8jch+ExBZ1DbNJO2Z9cZDYmA5rV6TQ0HOHXWPdd8vM/r8S0rPKjbqPdTD5R
3jsNiaepI7BViUJ5Pe3m7j30ca2aMuuJAVsG6cr7LZ7nvV94Yc4M3d2f+wtkF8V4i
4QaJfVIdg7zcg/M1NBHcMxMJQ1YfKpBXttoA7QG9uyG7IvN7/AkiuuZSzqW0QIDAQ
AB
-----END PUBLIC KEY-----`;

    const encrypt = new JSEncrypt();
    encrypt.setPublicKey(publicKey);

    const encryptedPassword = encrypt.encrypt(password);
    const encryptedUsername = usernameField ? encrypt.encrypt(username) : null;

    if (encryptedPassword && (usernameField == null || encryptedUsername)) {
        passwordField.value = encryptedPassword;
        if (usernameField) {
            usernameField.value = encryptedUsername;
        }
        event.target.submit();
    } else {
        console.error('Encryption failed.');
    }
});
</script>

<#-- Social Providers -->
<#elseif section = "socialProviders" >
    <#if realm.password && social.providers?? && social.providers?has_content>
        <@identityProviders.show social=social/>
    </#if>

<#-- Info Section -->
<#elseif section = "info" >
    <#if realm.password && realm.registrationAllowed && !registrationDisabled??>
        <div id="kc-registration-container">
            <div id="kc-registration">
                <span>${msg("noAccount")} <a href="${url.registrationUrl}">${msg("doRegister")}</a></span>
            </div>
        </div>
    </#if>
</#if>
</@layout.registrationLayout>
```

## Update `UsernamePasswordForm.java`

### Backup Existing File

```bash
mv services/src/main/java/org/keycloak/authentication/authenticators/browser/UsernamePasswordForm.java services/src/main/java/org/keycloak/authentication/authenticators/browser/UsernamePasswordForm_backup.java
```

### Create New `UsernamePasswordForm.java` class using the below command 

```bash
nano services/src/main/java/org/keycloak/authentication/authenticators/browser/UsernamePasswordForm.java
```

Paste the following content:

```java
package org.keycloak.authentication.authenticators.browser;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;

import jakarta.ws.rs.core.MultivaluedMap;

public class UsernamePasswordForm extends AbstractUsernameFormAuthenticator implements Authenticator {

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

        if (formData.containsKey("cancel")) {
            context.cancelLogin();
            return;
        }

        String encryptedPassword = formData.getFirst("password");
        String encryptedUsername = formData.getFirst("username");
        try {
            String decryptedUsername = decryptPassword(encryptedUsername);
            String decryptedPassword = decryptPassword(encryptedPassword);
            formData.putSingle("password", decryptedPassword);
            formData.putSingle("username", decryptedUsername);
        } catch (Exception e) {
            context.form().setError("Invalid encrypted password");
            return;
        }

        if (!validateForm(context, formData)) {
            return;
        }

        context.success();
    }

    private String decryptPassword(String encryptedPasswordBase64) throws Exception {
        PrivateKey privateKey = loadPrivateKey();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedPasswordBase64);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    private PrivateKey loadPrivateKey() throws Exception {
        String privateKeyPem = "...Your RSA Private Key...";
        privateKeyPem = privateKeyPem.replaceAll("-----\w+ PRIVATE KEY-----", "").replaceAll("\s+", "");
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyPem);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(spec);
    }
}
```

### 1. Create `constants.java` to hold keys use the below command to do this

```bash
nano services/src/main/java/org/keycloak/authentication/authenticators/browser/constants.java
```

Paste the following content
```
package org.keycloak.authentication.authenticators.browser;

public class constants {
    public static final String privateKeyPem =
    "-----BEGIN PRIVATE KEY-----\n" +
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDqNvwLvhFRS4oUKZ6so7CzGGg\n" +
    "f/3PIsTfcnjauTlOMmaUzYWkUsAJF4SOlEKhhDSoKDc+VjvChN99qBXuwFWuyvbomFCXUalK4geo\n" +
    "Pan3emYFV2/p9DlzQf2y9T/jL3JmTG3+Qcy0Q8pkB32635PYSbELHrNpjyNyH4TEFnUNs0k7Zn1x\n" +
    "kNiYDmtXpNDQc4ddY913y8z+vxLSs8qNuo91MPlHeOw2Jp6kjsFWJQnk97ebuPfRxrZoy64kBWwbp\n" +
    "yvstnue9X3hhzgzd3Z/7C2QXxXiLhBol9Uh2DvNyD8zU0EdwzEwlDVh8qkFe22gDtAb27Ibsi83v8\n" +
    "CSK65lLOpbRAgMBAAECggEABm/TqjpzZSOxdCenKtk2UVu7u9pkSxkUvxFRkSWJrgjodYKpNcZ3D4\n" +
    "bWGRKdwAoRtFRIFtUGd7XOg+5J5Y9XJgLJF4QQ/Jcd9iBq53jOpAQdvfd1WUPAaQIBgevtW2PxDA4\n" +
    "Sycxiig9SxW6Hr1HhceTsCmsNlvW1mt3lYCE/8cEB7zEpKMIIDGzbcnFEB7lOQdlIXfyw9CylLd5r\n" +
    "vecU0YUZNRVSYYlWh1D7CfXrAEtgoZOWhR52Oub6HuMFRfmeYGOvf9jW3ig6PLWLTUlj85GH9mFRV\n" +
    "6Sm581XmoYN2Umm1m4jv9YQFPirsf3ZpgUR7Cgts2HnfddMfntER4U6AQKBgQDuYMucXBBWjMtBIh\n" +
    "xm3KkY8yQ+5WAuxHPRfDN9wg2zCGbjPdWryxhQG8eg/ZQIuTbmzZPXxc3QxzHK0bJiX0BVKhqfaaA\n" +
    "mGg1qJiHALKwzrtE39DoCddXYSO03AdA9poMqMDFpJs1qMoku808ZQMo884d+hPkkdOwCQC5z2wc5\n" +
    "AQKBgQD7h2Zq2iiAvwKgDW/ALRMiZvTCKoISYJ2AGoq4QaySruE5jKcx1H0J8n+0/4a3+zfRx+gWE\n" +
    "Xv+vXni4D1Kn+mYz9w1NKATJ+IfgIdD+x3TwzqjtMKSfy0qN7iWqvZlgUWClPJYIdzyUVeS/gKUCM\n" +
    "tGMBTNDiNoQn6fgdTvLHAN0QKBgBLttL1RwipdO7aMUt0IIJVOmU41QJH2H4w+5IfT5OqWfDUHL/R\n" +
    "YSDH0QsHR4PNgYa+qG1dC6bjuWFHWnOea0KzyjvKhnInp/66yIHP2GCZyd0KOLh0L5lMqV0vK5RJA\n" +
    "KqIq+YF0B1Ord6E2yM0ki+qTG+s7+9ydPDBhkE660bQBAoGBAKRjSbxr+CysqbqRDYg77VV+lFiSD\n" +
    "5CTNFyU/DSQN4lmYiyKkHswtMfbhTt2BUYZGdIxJK3Hn5JNo2tzwpsTCEinEPR1AGmEl3SfO8hiRo\n" +
    "wv/BMiAEheddYxtKJD+eU9J4DAd+LBvvVf1CxtdqHpXXDx26Zopxts2fTFlbT7BgEBAoGAc9hY5ug\n" +
    "h8SWUXJcP6Xf5QpObZNIAeiYep9W/160e1JppWBfFgKMxB+f/rxyiII4b0gn9hqk6bEbPHRJIk7dh\n" +
    "hcLIxKlZFkTNuj53lWKAIWjmUwFKA0u1FUoVAfN1vthdI+/LhzpekPvVOKKxZ95WstEV8yFuVaS9x\n" +
    "hqyGIdQe2E=\n" +
    "-----END PRIVATE KEY-----\n";


    public static final String publicKeyPem =
    "-----BEGIN PUBLIC KEY-----\n" +
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6jb8C74RUUuKFCmerKOws\n" +
    "xhoH/9zyLE33J42rk5TjJmlM2FpFLACReEjpRCoYQ0qCg3PlY7woTffagV7sBVrsr\n" +
    "26JhQl1GpSuIHqD2p93pmBVdv6fQ5c0H9svU/4y9yZkxt/kHMtEPKZAd9ut+T2Emx\n" +
    "Cx6zaY8jch+ExBZ1DbNJO2Z9cZDYmA5rV6TQ0HOHXWPdd8vM/r8S0rPKjbqPdTD5R\n" +
    "3jsNiaepI7BViUJ5Pe3m7j30ca2aMuuJAVsG6cr7LZ7nvV94Yc4M3d2f+wtkF8V4i\n" +
    "4QaJfVIdg7zcg/M1NBHcMxMJQ1YfKpBXttoA7QG9uyG7IvN7/AkiuuZSzqW0QIDAQ\n" +
    "AB\n" +
    "-----END PUBLIC KEY-----\n";
}

```

### Compile the Code
```
mvn clean install -DskipTests
```

### Starting Keycloak

To start Keycloak during development first build as specified above, then run:
```java
    java -jar quarkus/server/target/lib/quarkus-run.jar start-dev
```
To stop the server press `Ctrl + C`.

---


## 🧑‍💼 2. Create an Admin Account

1. Open your browser and visit: `http://localhost:8080`
2. You’ll be prompted to **create an admin account**.
   - Choose a **username** and **password** of your choice.
3. Click **Create** to proceed.

---

## 🏛️ 3. Create a Realm

1. After logging in with your admin account:
2. Click **Manage Realms** on the left sidebar.
3. Click **Add Realm**.
   - Provide a **name** for your new realm (e.g., `myrealm`).
   - Click **Create**.

---

## 👤 4. Create a New User

1. Inside your new realm:
2. Go to the **Users** section.
3. Click **Add User**.
   - Fill in the required fields (e.g., **username**).
   - Click **Save**.
4. Navigate to the **Credentials** tab for the user.
5. Set a **password** and turn **Temporary** off.
6. Click **Set Password**.

---

## 💻 5. Create or Configure a Client

1. Go to the **Clients** section.
2. Either create a new client or use the existing one (`account`).
3. Ensure it uses **OpenID Connect** and has the **Standard Flow** enabled.

---

## 🔗 6. Open the Login Page

1. From the **Clients** section:
2. Click the **account** client (or the one you created).
3. Go to the **Installation** or **Settings** tab.
4. Find the **Login URL** (e.g., `http://localhost:8080/realms/myrealm/account`).
5. Open this URL in your browser — it will take you to the **login page**.

---

## 🧪 7. Inspect the Login Request

1. Enter the username and password of the user you created earlier.
2. **Before clicking "Sign In"**:
   - Open **Browser Developer Tools** (usually `F12`).
   - Go to the **Network** tab.
3. Click **Sign In**.
4. In the Network tab:
   - Look for a **POST request** to `/realms/<your-realm>/protocol/openid-connect/auth` or `/token`.
   - Click the request and inspect the **Request Payload**.

---

## 🔍 8. Verify Encryption

- In the **Request Payload**, check whether the **username** and **password** are encrypted.
  - If your custom authenticator is working correctly, the password should **not appear in plain text**.

---
