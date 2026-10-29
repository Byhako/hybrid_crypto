use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::RngCore;
use rand::rngs::OsRng;
use std::fs;
use std::path::Path;
use x25519_dalek::{PublicKey, StaticSecret};

/// 1. Inicializa y genera el par de llaves si no existen en el disco
fn initialize_keys() {
    if !Path::new("private_key.bin").exists() || !Path::new("public_key.bin").exists() {
        println!("[+] Generando par de llaves iniciales...");
        let secret_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret_key);

        fs::write("private_key.bin", secret_key.as_bytes()).unwrap();
        fs::write("public_key.bin", public_key.as_bytes()).unwrap();
        println!("[+] Llaves guardadas exitosamente en el disco.");
    }
}

/// 2. Cifra un mensaje de manera híbrida usando la llave pública del destinatario
fn encrypt_message(recipient_public_key: &PublicKey, plaintext: &str) -> Vec<u8> {
    // Generamos par efímero del remitente
    let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    // Diffie-Hellman para obtener secreto compartido
    let shared_secret = ephemeral_secret.diffie_hellman(recipient_public_key);

    // Configuración AES-GCM
    let aes_key = Key::<Aes256Gcm>::from_slice(shared_secret.as_bytes());
    let cipher = Aes256Gcm::new(aes_key);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .expect("Error durante el cifrado AES");

    // Empaquetamos en el sobre digital: [32 bytes pub_remitente] + [12 bytes nonce] + [ciphertext]
    let mut envelope = Vec::new();
    envelope.extend_from_slice(ephemeral_public.as_bytes());
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&ciphertext);

    envelope
}

/// 3. Descifra un sobre digital usando la llave privada del destinatario
fn decrypt_message(recipient_private_key: &StaticSecret, envelope_bytes: &[u8]) -> String {
    if envelope_bytes.len() < 32 + 12 {
        panic!("El archivo del sobre está corrupto o incompleto.");
    }

    // Extraer componentes del sobre
    let mut sender_pub_array = [0u8; 32];
    sender_pub_array.copy_from_slice(&envelope_bytes[0..32]);
    let sender_ephemeral_public = PublicKey::from(sender_pub_array);

    let mut decrypted_nonce_bytes = [0u8; 12];
    decrypted_nonce_bytes.copy_from_slice(&envelope_bytes[32..44]);
    let decrypted_nonce = Nonce::from_slice(&decrypted_nonce_bytes);

    let decrypted_ciphertext = &envelope_bytes[44..];

    // Diffie-Hellman inverso
    let decrypted_shared_secret = recipient_private_key.diffie_hellman(&sender_ephemeral_public);

    // Reconstruir AES y descifrar
    let decrypted_aes_key = Key::<Aes256Gcm>::from_slice(decrypted_shared_secret.as_bytes());
    let decrypted_cipher = Aes256Gcm::new(decrypted_aes_key);

    let plaintext_bytes = decrypted_cipher
        .decrypt(decrypted_nonce, decrypted_ciphertext)
        .expect("Error al descifrar: ¿Llave incorrecta o sobre alterado?");

    String::from_utf8(plaintext_bytes).expect("El mensaje descifrado no es texto UTF-8 válido")
}

/// 4. Orquestador principal
fn main() {
    println!("--- Sistema de Cifrado Híbrido Modular en Rust ---");

    // Paso A: Asegurar identidad / llaves
    initialize_keys();

    // Mensaje de prueba
    let mensaje_original =
        "¡Hola Ruben! Arquitectura modular y limpia separando responsabilidades.";
    println!("\n[1] Mensaje original: \"{}\"", mensaje_original);

    // Paso B: Cargar la llave pública del destinatario
    let pub_bytes = fs::read("public_key.bin").expect("No se pudo leer la llave pública");
    let mut pub_array = [0u8; 32];
    pub_array.copy_from_slice(&pub_bytes);
    let recipient_public_key = PublicKey::from(pub_array);

    // Paso C: Cifrar y guardar el sobre
    let envelope = encrypt_message(&recipient_public_key, mensaje_original);
    fs::write("envelope.bin", envelope).expect("Error al guardar el sobre digital");
    println!("[2] ¡Éxito! Mensaje cifrado y guardado en 'envelope.bin'.");

    // Paso D: Leer el sobre y descifrarlo usando nuestra llave privada
    println!("\n[3] Leyendo y descifrando 'envelope.bin'...");
    let envelope_bytes = fs::read("envelope.bin").expect("No se pudo leer el sobre digital");

    let priv_bytes = fs::read("private_key.bin").expect("No se pudo leer la llave privada");
    let mut priv_array = [0u8; 32];
    priv_array.copy_from_slice(&priv_bytes);
    let recipient_private_key = StaticSecret::from(priv_array);

    let mensaje_recuperado = decrypt_message(&recipient_private_key, &envelope_bytes);
    println!("[4] ¡Descifrado exitoso!");
    println!("   -> Mensaje recuperado: \"{}\"", mensaje_recuperado);
}
