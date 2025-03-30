package main

import (
	"crypto"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/rand"
	"strconv"
	"time"
)

func GenerateIBAN() string {
	rand.Seed(time.Now().UnixNano())

	var result string = "UA"
	for i := 0; i < 8; i++ {
		number := rand.Intn(10)
		result += strconv.Itoa(number)
	}
	result += "00000"
	for i := 0; i < 14; i++ {
		number := rand.Intn(10)
		result += strconv.Itoa(number)
	}
	return result
}
func GenerationEDRPOU() string {
	rand.Seed(time.Now().UnixNano())

	var result string
	for i := 0; i < 10; i++ {
		number := rand.Intn(10)
		result += strconv.Itoa(number)
	}
	return result
}
func GenerationRSA() (*rsa.PrivateKey, string, error) {
	// Генеруємо приватний ключ
	privateKey, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		return nil, "", err
	}

	// Експортуємо публічний ключ у PEM формат
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, "", err
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return privateKey, string(publicKeyPEM), nil
}
func Generatehash(input string) [32]byte {
	var hash [32]byte = sha256.Sum256([]byte(input))
	return hash
}
func CreateDualSignature(privateKey *rsa.PrivateKey, recipient [32]byte, iban [32]byte, edrpou [32]byte, appointment [32]byte) ([]byte, error) {
	// Об'єднуємо хеші
	combinedHash := sha256.Sum256(append(append(append(recipient[:], iban[:]...), edrpou[:]...), appointment[:]...))

	// Підписуємо комбінований хеш
	signature, err := rsa.SignPKCS1v15(crand.Reader, privateKey, crypto.SHA256, combinedHash[:])
	if err != nil {
		return nil, err
	}
	return signature, nil
}
func VerifyDualSignature(publicKeyPEM string, signature []byte, edrpouHash [32]byte) error {
	// Розшифровуємо публічний ключ із PEM-формату
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return fmt.Errorf("не вдалося декодувати PEM")
	}

	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("не вдалося розшифрувати публічний ключ: %v", err)
	}

	// Перетворюємо інтерфейс у *rsa.PublicKey
	publicKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("публічний ключ не є типом RSA")
	}

	// Перевіряємо підпис
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, edrpouHash[:], signature)
	if err != nil {
		return fmt.Errorf("Підпис недійсний: %v", err)
	}

	return nil
}
func main() {
	recipient := "Калинець Ігор Миронович"
	fmt.Printf("Одержувач:%s\n", recipient)
	iban := GenerateIBAN()
	fmt.Printf("IBAN:%s\n", iban)
	EDRPOU := GenerationEDRPOU()
	fmt.Printf("ЄДРПОУ:%s\n", EDRPOU)
	payment_appointment := "Шевчук Валерій Олександрович. Для сплати книг"
	fmt.Printf("Призначення платежу:%s\n\n", payment_appointment)

	privateKey, publicKey, err := GenerationRSA()
	if err != nil {
		fmt.Println("Помилка генерації RSA ключа:", err)
		return
	}

	hash_recipient := Generatehash(recipient)
	hash_iban := Generatehash(iban)
	hash_edrpou := Generatehash(EDRPOU)
	hash_payment_appointment := Generatehash(payment_appointment)
	fmt.Println("Хеш одержувача у вигляді рядка:", hex.EncodeToString(hash_recipient[:]))
	fmt.Println("Хеш IBAN у вигляді рядка:", hex.EncodeToString(hash_iban[:]))
	fmt.Println("Хеш ЄДРПОУ у вигляді рядка:", hex.EncodeToString(hash_edrpou[:]))
	fmt.Println("Хеш призначення платежу у вигляді рядка:", hex.EncodeToString(hash_payment_appointment[:]))
	dualsignature, err := CreateDualSignature(privateKey, hash_recipient, hash_iban, hash_edrpou, hash_payment_appointment)
	fmt.Printf("\nДуальний підпис: %x\n", dualsignature)
	combinedHash := sha256.Sum256(append(append(append(hash_recipient[:], hash_iban[:]...), hash_edrpou[:]...), hash_payment_appointment[:]...))
	err = VerifyDualSignature(publicKey, dualsignature, combinedHash)
	if err != nil {
		fmt.Println("\nПомилка перевірки підпису:", err)
	} else {
		fmt.Println("\nПідпис дійсний.")
	}
}
