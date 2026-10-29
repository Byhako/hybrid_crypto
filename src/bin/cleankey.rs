use keyring::Entry;
use std::fs;
use std::path::Path;

const SERVICE_NAME: &str = "hybrid_crypto_rust";
const USER_KEY_NAME: &str = "recipient_private_key";

fn main() {
    // 1. Intentamos borrar del Keyring
    match Entry::new(SERVICE_NAME, USER_KEY_NAME) {
        Ok(entry) => match entry.delete_password() {
            Ok(_) => println!("[-] Llave privada eliminada exitosamente del Keyring del S.O."),
            Err(e) => println!(
                "[-] No se encontró la llave privada en el Keyring o ya fue borrada: {}",
                e
            ),
        },
        Err(e) => println!("[-] No se pudo acceder al Keyring: {}", e),
    }

    // 2. Borramos el archivo de la llave pública local si existe
    if Path::new("public_key.bin").exists() && fs::remove_file("public_key.bin").is_ok() {
        println!("[-] Archivo 'public_key.bin' eliminado localmente.");
    }

    // 3. Opcional: Borramos también el sobre digital de prueba si existe
    if Path::new("envelope.bin").exists() {
        let _ = fs::remove_file("envelope.bin");
        println!("[-] Archivo 'envelope.bin' de prueba eliminado.");
    }
}
