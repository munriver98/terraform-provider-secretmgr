package secretmgr

import (
	// "encoding/json"

	"bytes"
	"fmt"
	"io/ioutil"
	"log"

	"encoding/base64"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
	"golang.org/x/crypto/openpgp"
)

func resourceDecryptAwsSecret() *schema.Resource {
	return &schema.Resource{
		SchemaVersion: 1,

		Create: decryptAwsSecretResourceWrite,
		// Update: gpgResourceUpdate,
		Delete: decryptAwsSecretResourceDelete,
		Read:   decryptAwsSecretResourceRead,
		// Importer: &schema.ResourceImporter{
		// 	State: schema.ImportStatePassthrough,
		// },
		// MigrateState: resourceUserMigrateState,

		Schema: map[string]*schema.Schema{
			"access_key": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Sensitive:   true,
				Description: "access_key",
			},
			"encrypted_secret": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Sensitive:   true,
				Description: "encrypted_secret",
			},
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "path",
			},
			"gpg_private_path": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "gpg_private_path",
			},
		},
	}
}

func decryptWithGpg(gpg_private_path string, encrypted_secret string, client *api.Client) (string, error) {

	secret, err := versionedSecret(0, gpg_private_path, client)
	if err != nil {
		return "", err
	}
	if secret == nil {
		log.Printf("[WARN] secret (%s) not found, removing from state", gpg_private_path)
		return "", nil
	}

	privateKeyString := secret.Data["KEY"].(string)
	privateKeyByte, err := base64.StdEncoding.DecodeString(privateKeyString)
	if err != nil {
		return "", err
	}

	entityList, err := openpgp.ReadKeyRing(bytes.NewBuffer(privateKeyByte))
	if err != nil {
		return "", err
	}
	// Decode the base64 string
	dec, err := base64.StdEncoding.DecodeString(encrypted_secret)
	if err != nil {
		return "", err
	}

	// Decrypt it with the contents of the private key
	md, err := openpgp.ReadMessage(bytes.NewBuffer(dec), entityList, nil, nil)
	if err != nil {
		return "", err
	}
	bytes, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", err
	}
	decStr := string(bytes)

	return decStr, nil
}

func decryptAwsSecretResourceWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	encrypted_secret := d.Get("encrypted_secret").(string)
	path := d.Get("path").(string)
	originalPath := path
	gpg_private_path := d.Get("gpg_private_path").(string)
	access_key := d.Get("access_key").(string)

	decryptSecretKey, err := decryptWithGpg(gpg_private_path, encrypted_secret, client)
	if err != nil {
		return fmt.Errorf("error decrypting aws secret key: %s", err)
	}

	payLoad := map[string]interface{}{
		"AWS_ACCESS_KEY": access_key,
		"AWS_SECRET_KEY": decryptSecretKey,
	}

	err = addVersionedSecret(path, &payLoad, client)
	if err != nil {
		return fmt.Errorf("error add secret : %s", err)
	}

	d.SetId(originalPath)

	return decryptAwsSecretResourceRead(d, meta)
}

func decryptAwsSecretResourceRead(d *schema.ResourceData, meta interface{}) error {

	path := d.Id()

	client := meta.(*api.Client)

	log.Printf("[DEBUG] Reading %s from Vault", path)
	secret, err := versionedSecret(latestSecretVersion, path, client)

	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}
	if secret == nil {
		log.Printf("[WARN] secret (%s) not found, removing from state", path)
		d.SetId("")
		return nil
	}

	log.Printf("[DEBUG] secret: %#v", secret)

	return nil
}

func decryptAwsSecretResourceDelete(d *schema.ResourceData, meta interface{}) error {

	path := d.Id()

	client := meta.(*api.Client)

	mountPath, v2, err := isKVv2(path, client)
	if err != nil {
		return fmt.Errorf("error determining if it's a v2 path: %s", err)
	}

	if v2 {
		path = addPrefixToVKVPath(path, mountPath, "metadata")
	}

	log.Printf("[DEBUG] Delete %s from Vault", path)

	err = deleteSecretCascade(path, meta)
	if err != nil {
		return fmt.Errorf("error deleting path: %s", err)
	}

	return nil
}
