package secretmgr

import (
	// "encoding/json"

	"fmt"
	"log"

	PATH "path"

	"encoding/base64"

	"github.com/alokmenghrajani/gpgeez"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

func resourceGpg() *schema.Resource {
	return &schema.Resource{
		SchemaVersion: 1,

		Create: gpgResourceWrite,
		// Update: gpgResourceUpdate,
		Delete: gpgResourceDelete,
		Read:   gpgResourceRead,
		// Importer: &schema.ResourceImporter{
		// 	State: schema.ImportStatePassthrough,
		// },
		// MigrateState: resourceUserMigrateState,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "name",
			},
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "path",
			},
			"create_date": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "date",
			},
			"privatekey_path": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Path of the private key.",
			},
			"publickey_path": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Path of the public key.",
			},
		},
	}
}

func gpgResourceWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	name := d.Get("name").(string)
	path := d.Get("path").(string)

	originalPath := path

	pubPath := PATH.Join(path, "public")
	privPath := PATH.Join(path, "private")

	config := gpgeez.Config{Expiry: 0}
	key, err := gpgeez.CreateKey(name, "", "", &config)
	if err != nil {
		return fmt.Errorf("error generate gpg's key from Vault: %s", err)
	}

	payLoad := map[string]interface{}{
		"KEY": base64.StdEncoding.EncodeToString(key.Keyring()),
	}

	err = addVersionedSecret(pubPath, &payLoad, client)
	if err != nil {
		return fmt.Errorf("error add secret : %s", err)
	}

	payLoad = map[string]interface{}{
		"KEY": base64.StdEncoding.EncodeToString(key.Secring(&config)),
	}

	err = addVersionedSecret(privPath, &payLoad, client)
	if err != nil {
		return fmt.Errorf("error add secret : %s", err)
	}

	d.Set("privatekey_path", privPath)
	d.Set("publickey_path", pubPath)

	d.SetId(originalPath)

	return gpgResourceRead(d, meta)
}

func gpgResourceRead(d *schema.ResourceData, meta interface{}) error {

	publickey_path := d.Get("publickey_path").(string)

	client := meta.(*api.Client)

	log.Printf("[DEBUG] Reading %s from Vault", publickey_path)
	secret, err := versionedSecret(latestSecretVersion, publickey_path, client)

	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}
	if secret == nil {
		log.Printf("[WARN] secret (%s) not found, removing from state", publickey_path)
		d.SetId("")
		return nil
	}

	log.Printf("[DEBUG] secret: %#v", secret)

	return nil
}

func gpgResourceDelete(d *schema.ResourceData, meta interface{}) error {

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
