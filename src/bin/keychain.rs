use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use keyring::Entry;
use rand::RngCore;
use rand::rngs::OsRng;
use std::fs;
use std::path::Path;
use x25519_dalek::{PublicKey, StaticSecret};

const SERVICE_NAME: &str = "hybrid_crypto_rust";
const USER_KEY_NAME: &str = "recipient_private_key";

/// 1. Inicializa las llaves: Guarda la privada en el Keyring del S.O. y la pública en archivo
fn initialize_keys() -> PublicKey {
    // Verificamos en una sola línea limpia si la entrada existe y tiene contraseña guardada
    let credentials_exist = Entry::new(SERVICE_NAME, USER_KEY_NAME)
        .and_then(|entry| entry.get_password())
        .is_ok();

    if credentials_exist && Path::new("public_key.bin").exists() {
        println!("[+] Llave privada ya existe en el Keyring del S.O. Recuperando llave pública...");
        let pub_bytes = fs::read("public_key.bin").unwrap();
        let mut pub_array = [0u8; 32];
        pub_array.copy_from_slice(&pub_bytes);
        return PublicKey::from(pub_array);
    }

    println!(
        "[+] No se encontraron credenciales previas o el Keyring no está disponible. Generando nuevo par seguro..."
    );
    let secret_key = StaticSecret::random_from_rng(OsRng);
    let public_key = PublicKey::from(&secret_key);

    // Guardar clave privada en el Keyring de forma segura
    let entry = Entry::new(SERVICE_NAME, USER_KEY_NAME)
        .expect("No se pudo inicializar el keyring del sistema operativo");
    let secret_hex = hex::encode(secret_key.as_bytes());
    entry
        .set_password(&secret_hex)
        .expect("Error al guardar la llave privada en el Keyring");

    // Guardar llave pública en archivo
    fs::write("public_key.bin", public_key.as_bytes()).unwrap();

    println!("[+] ¡Éxito! Llave privada resguardada en el Keyring de tu S.O.");
    println!("[+] Llave pública guardada en 'public_key.bin'.");

    public_key
}

/// Carga la llave privada directamente desde el Keychain del S.O.
fn load_private_key() -> StaticSecret {
    // Manejamos el Result que devuelve Entry::new en keyring v2.0+
    let entry = Entry::new(SERVICE_NAME, USER_KEY_NAME)
        .expect("No se pudo inicializar la entrada del keyring");

    let secret_hex = entry
        .get_password()
        .expect("No se encontró la llave privada en el Keyring. ¿Ejecutaste la inicialización?");

    let secret_bytes =
        hex::decode(secret_hex).expect("Error al decodificar la llave privada del Keyring");

    let mut priv_array = [0u8; 32];
    priv_array.copy_from_slice(&secret_bytes);

    StaticSecret::from(priv_array)
}

/// 2. Cifra un mensaje usando la llave pública del destinatario
fn encrypt_message(recipient_public_key: &PublicKey, plaintext: &str) -> Vec<u8> {
    let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    let shared_secret = ephemeral_secret.diffie_hellman(recipient_public_key);

    let aes_key = Key::<Aes256Gcm>::from_slice(shared_secret.as_bytes());
    let cipher = Aes256Gcm::new(aes_key);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .expect("Error durante el cifrado AES");

    // Empaquetamos: [32 bytes pub_remitente] + [12 bytes nonce] + [ciphertext]
    let mut envelope = Vec::new();
    envelope.extend_from_slice(ephemeral_public.as_bytes());
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&ciphertext);

    envelope
}

/// 3. Descifra un sobre digital usando la llave privada obtenida del Keyring
fn decrypt_message(recipient_private_key: &StaticSecret, envelope_bytes: &[u8]) -> String {
    if envelope_bytes.len() < 32 + 12 {
        panic!("El archivo del sobre está corrupto o incompleto.");
    }

    let mut sender_pub_array = [0u8; 32];
    sender_pub_array.copy_from_slice(&envelope_bytes[0..32]);
    let sender_ephemeral_public = PublicKey::from(sender_pub_array);

    let mut decrypted_nonce_bytes = [0u8; 12];
    decrypted_nonce_bytes.copy_from_slice(&envelope_bytes[32..44]);
    let decrypted_nonce = Nonce::from_slice(&decrypted_nonce_bytes);

    let decrypted_ciphertext = &envelope_bytes[44..];

    let decrypted_shared_secret = recipient_private_key.diffie_hellman(&sender_ephemeral_public);

    let decrypted_aes_key = Key::<Aes256Gcm>::from_slice(decrypted_shared_secret.as_bytes());
    let decrypted_cipher = Aes256Gcm::new(decrypted_aes_key);

    let plaintext_bytes = decrypted_cipher
        .decrypt(decrypted_nonce, decrypted_ciphertext)
        .expect("Error al descifrar: ¿Llave incorrecta o sobre alterado?");

    String::from_utf8(plaintext_bytes).expect("El mensaje descifrado no es texto UTF-8 válido")
}

/// 4. Orquestador principal
fn main() {
    println!("--- Sistema de Cifrado Híbrido con Keyring (Nivel Producción) ---");

    // Paso A: Inicializar llaves (la privada va al Keychain del S.O.)
    let recipient_public_key = initialize_keys();

    // Mensaje de prueba
    let mensaje_original = "¡Hola Ruben! Este mensaje está protegido con llaves almacenadas en el Keyring del sistema operativo.";
    println!("\n[1] Mensaje original: \"{}\"", mensaje_original);

    // Paso B: Cifrar y guardar el sobre digital
    let envelope = encrypt_message(&recipient_public_key, mensaje_original);
    fs::write("envelope.bin", envelope).expect("Error al guardar el sobre digital");
    println!("[2] ¡Éxito! Mensaje cifrado y guardado en 'envelope.bin'.");

    // Paso C: Leer el sobre y descifrarlo cargando la llave privada desde el Keyring
    println!("\n[3] Leyendo 'envelope.bin' y pidiendo la llave privada al Keyring del S.O...");
    let envelope_bytes = fs::read("envelope.bin").expect("No se pudo leer el sobre digital");

    // Recuperamos la llave privada de forma segura desde el gestor del S.O.
    let recipient_private_key = load_private_key();

    let mensaje_recuperado = decrypt_message(&recipient_private_key, &envelope_bytes);
    println!("[4] ¡Descifrado exitoso!");
    println!("   -> Mensaje recuperado: \"{}\"", mensaje_recuperado);
}
