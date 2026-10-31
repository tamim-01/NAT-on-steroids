package main

import (
	"context"
	"errors"
	"time"

	"github.com/godbus/dbus/v5"
)

var errKeyringLocked = errors.New("desktop keyring is locked")

const secretName = "org.freedesktop.secrets"
const secretService = "org.freedesktop.Secret.Service"

type secretValue struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

// Bound non-interactive calls: an unlock prompt must not stall the VPN or exit.
func keyringOperation(operation, data string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := dbus.ConnectSessionBus(dbus.WithContext(ctx))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	service := conn.Object(secretName, "/org/freedesktop/secrets")
	// Keep the original storage identifier so version 0.1 sign-ins can migrate.
	attributes := map[string]string{"service": "foxyvpn-linux", "username": "default"}
	var unlocked, locked []dbus.ObjectPath
	if err = service.CallWithContext(ctx, secretService+".SearchItems", 0, attributes).Store(&unlocked, &locked); err != nil {
		return "", err
	}
	if len(locked) > 0 {
		return "", errKeyringLocked
	}
	if operation == "delete" {
		for _, item := range unlocked {
			var prompt dbus.ObjectPath
			if err = conn.Object(secretName, item).CallWithContext(ctx, "org.freedesktop.Secret.Item.Delete", 0).Store(&prompt); err != nil {
				return "", err
			}
			if prompt != "/" {
				return "", errKeyringLocked
			}
		}
		return "", nil
	}
	if operation == "get" && len(unlocked) == 0 {
		return "", nil
	}
	var collection dbus.ObjectPath
	if operation == "set" {
		if err = service.CallWithContext(ctx, secretService+".ReadAlias", 0, "default").Store(&collection); err != nil {
			return "", err
		}
		if collection == "/" {
			return "", errors.New("desktop keyring has no default collection")
		}
		var locked dbus.Variant
		if err = conn.Object(secretName, collection).CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, "org.freedesktop.Secret.Collection", "Locked").Store(&locked); err != nil {
			return "", err
		}
		if isLocked, _ := locked.Value().(bool); isLocked {
			return "", errKeyringLocked
		}
	}
	var session dbus.ObjectPath
	var negotiated dbus.Variant
	if err = service.CallWithContext(ctx, secretService+".OpenSession", 0, "plain", dbus.MakeVariant("")).Store(&negotiated, &session); err != nil {
		return "", err
	}
	if operation == "get" {
		var value secretValue
		if err = conn.Object(secretName, unlocked[0]).CallWithContext(ctx, "org.freedesktop.Secret.Item.GetSecret", 0, session).Store(&value); err != nil {
			return "", err
		}
		return string(value.Value), nil
	}
	properties := map[string]dbus.Variant{"org.freedesktop.Secret.Item.Label": dbus.MakeVariant("NAT-on-steroids Mozilla accounts"), "org.freedesktop.Secret.Item.Attributes": dbus.MakeVariant(attributes)}
	var item, prompt dbus.ObjectPath
	err = conn.Object(secretName, collection).CallWithContext(ctx, "org.freedesktop.Secret.Collection.CreateItem", 0, properties, secretValue{session, []byte{}, []byte(data), "text/plain; charset=utf8"}, true).Store(&item, &prompt)
	if err != nil {
		return "", err
	}
	if prompt != "/" {
		return "", errKeyringLocked
	}
	return "", nil
}
