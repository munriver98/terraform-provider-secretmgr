package secretmgr

import (
	// "encoding/json"
	"fmt"
	"log"
	PATH "path"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

const latestSecretVersion = -1

func resourceUser() *schema.Resource {
	return &schema.Resource{
		SchemaVersion: 1,

		Create: userResourceWrite,
		// Update: userResourceUpdate,
		Delete: userResourceDelete,
		Read:   userResourceRead,
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
			"base_path": {
				Type:        schema.TypeString,
				ForceNew:    true,
				Optional:    true,
				Default:     "sre-secrets/users",
				Description: "base_path",
			},
		},
	}
}

func userResourceWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	var data map[string]interface{}

	name := d.Get("name").(string)
	basePath := d.Get("base_path").(string)

	path := PATH.Join(basePath, name)
	originalPath := path

	mountPath, v2, err := isKVv2(path, client)
	if err != nil {
		return fmt.Errorf("error reading if it's a v2 path: %s", err)
	}

	if v2 {
		path = addPrefixToVKVPath(path, mountPath, "data")
	}

	examplePath := PATH.Join(path, "example")

	payLoad := map[string]interface{}{
		"example": "You should not delete this.",
	}

	data = map[string]interface{}{
		"data":    payLoad,
		"options": map[string]interface{}{},
	}

	log.Printf("[DEBUG] Writing generic Vault secret to %s", path)
	_, err = client.Logical().Write(examplePath, data)
	if err != nil {
		return fmt.Errorf("error writing to Vault: %s", err)
	}

	d.SetId(originalPath)

	return userResourceRead(d, meta)
}

func userResourceRead(d *schema.ResourceData, meta interface{}) error {

	path := d.Id()

	client := meta.(*api.Client)

	examplePath := PATH.Join(path, "example")

	log.Printf("[DEBUG] Reading %s from Vault", examplePath)
	secret, err := versionedSecret(latestSecretVersion, examplePath, client)

	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}
	if secret == nil {
		log.Printf("[WARN] secret (%s) not found, removing from state", examplePath)
		d.SetId("")
		return nil
	}

	log.Printf("[DEBUG] secret: %#v", secret)

	return nil
}

func userResourceDelete(d *schema.ResourceData, meta interface{}) error {

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

	userResourceDeleteAll(path, meta)

	return nil
}

func userResourceDeleteAll(path string, meta interface{}) error {

	client := meta.(*api.Client)

	log.Printf("[DEBUG] listing %s from Vault", path)

	secret, err := client.Logical().List(path)
	if err != nil {
		return fmt.Errorf("error listing %q from Vault: %q", path, err)
	}

	for _, v := range secret.Data["keys"].([]interface{}) {
		key := v.(string)

		log.Printf("[DEBUG] key - %s ", key)

		if key[len(key)-1:] == "/" {
			userResourceDeleteAll(PATH.Join(path, key[:len(key)-1]), meta)
		} else {
			subPath := PATH.Join(path, key)
			log.Printf("[DEBUG] deleting %s from Vault", subPath)
			_, err = client.Logical().Delete(subPath)
			if err != nil {
				return fmt.Errorf("error deleting %q from Vault: %q", subPath, err)
			}
		}
	}

	return nil
}
