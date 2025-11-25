async function getKeyFromPassword(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        "raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 250000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

async function encryptFile() {
    const fileInput = document.getElementById("encryptFile").files[0];
    const password = document.getElementById("encryptPass").value;

    if (!fileInput || !password) return alert("Select file & enter password");

    const fileData = await fileInput.arrayBuffer();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const key = await getKeyFromPassword(password, salt);

    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        fileData
    );

    const blob = new Blob([salt, iv, new Uint8Array(encrypted)], {
        type: "application/octet-stream"
    });

    const link = document.getElementById("downloadEncrypted");
    link.href = URL.createObjectURL(blob);
    link.download = fileInput.name + ".encrypted";
    link.textContent = "Download Encrypted File";
}

async function decryptFile() {
    const fileInput = document.getElementById("decryptFile").files[0];
    const password = document.getElementById("decryptPass").value;

    if (!fileInput || !password) return alert("Select file & enter password");

    const encrypted = new Uint8Array(await fileInput.arrayBuffer());

    const salt = encrypted.slice(0, 16);
    const iv = encrypted.slice(16, 28);
    const data = encrypted.slice(28);

    const key = await getKeyFromPassword(password, salt);

    try {
        const decrypted = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            data
        );

        const blob = new Blob([decrypted]);

        const link = document.getElementById("downloadDecrypted");
        link.href = URL.createObjectURL(blob);
        link.download = fileInput.name.replace(".encrypted", "");
        link.textContent = "Download Decrypted File";

    } catch (e) {
        alert("Incorrect password or corrupted file");
    }
}
