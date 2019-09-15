// Go NETCONF Client
//
// Copyright (c) 2013-2018, Juniper Networks, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package netconf

import (
	"bytes"
	"crypto/rand"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

// Structs

type AddressBookXML struct {
	XMLName  xml.Name `xml:"address-book,omitempty"`
	Name       string          `xml:"name,omitempty"`
	Address    []AddressXML    `xml:"address,omitempty"`
	AddressSet []AddressSetXML `xml:"address-set,omitempty"`
}

type AddressXML struct {
	XMLOperation string `xml:"operation,attr,omitempty"`
	Name        string `xml:"name,omitempty"`
	Description string `xml:"description,omitempty"`
	IPPrefix    string `xml:"ip-prefix,omitempty"`
}

type AddressSetXML struct {
	XMLName  xml.Name `xml:"address-set,omitempty"`
	XMLOperation string `xml:"operation,attr,omitempty"`
	Name           string          `xml:"name,omitempty"`
	AddressSetName string          `xml:"address-set-name,omitempty"`
	Description    string          `xml:"description,omitempty"`
	Address        []AddressXML    `xml:"address,omitempty"`
	AddressSet     []AddressSetXML `xml:"address-set,omitempty"`
}

type ConfigurationXML struct {
	XMLName  xml.Name `xml:"configuration,omitempty"`
	Security struct {
		AddressBook AddressBookXML `xml:"address-book,omitempty"`
	} `xml:"security,omitempty"`
}
func trimXML(str string) string {
	str = strings.Replace(str, "\t", "", -1)
	return strings.Replace(str, "\n", "", -1)
}

// ToRawMethod chain xml string with marshalled xml
func (c ConfigurationXML)ToRawMethod() RawMethod {
	getConfigFmt :=
	`<get-config>
		<source>
			<running/>
		</source>
		<filter type=\"subtree\">
			%s
		</filter>
	</get-config>`
	xmlStr ,_ := xml.Marshal(c)
	fullXML := fmt.Sprintf(getConfigFmt, xmlStr)
	return RawMethod(trimXML(fullXML))
}

type DataXML struct {
	XMLName  xml.Name `xml:"data,omitempty"`
	Configuration ConfigurationXML `xml:"configuration"`
}

type EditConfigXML struct {
	XMLName  xml.Name `xml:"configuration,omitempty"`
	Security struct {
		AddressBook AddressBookXML `xml:"address-book,omitempty"`
	} `xml:"security,omitempty"`
}

func (ec EditConfigXML) ToRawMethod() RawMethod {
	editConfigFmt :=
	`<edit-config> 
		<target> 
			<candidate/> 
		</target>
		<config>
			%s
		</config>
	</edit-config>`
	xmlStr, _ := xml.Marshal(ec)
	return RawMethod(trimXML(fmt.Sprintf(editConfigFmt, xmlStr)))
}

type DeleteConfigXML struct {
	XMLName  xml.Name `xml:"configuration,omitempty"`
	Security struct {
		AddressBook AddressBookXML `xml:"address-book,omitempty"`
	} `xml:"security,omitempty"`
}

func (dc DeleteConfigXML) ToRawMethod() RawMethod {
	for i, _ := range dc.Security.AddressBook.AddressSet {
		dc.Security.AddressBook.AddressSet[i].XMLOperation = "delete"
	}
	for i, _ := range dc.Security.AddressBook.Address {
		dc.Security.AddressBook.Address[i].XMLOperation = "delete"
	}
	deleteConfigFmt :=
	`<edit-config>
		<target>
			<candidate/>
		</target>
		<config>
			%s
		</config>
	</edit-config>`
	xmlStr, _ := xml.Marshal(dc)
	return RawMethod(trimXML(fmt.Sprintf(deleteConfigFmt, xmlStr)))
}

// RPCMessage represents an RPC Message to be sent.
type RPCMessage struct {
	MessageID string
	Methods   []RPCMethod
}

// NewRPCMessage generates a new RPC Message structure with the provided methods
func NewRPCMessage(methods []RPCMethod) *RPCMessage {
	return &RPCMessage{
		MessageID: msgID(),
		Methods:   methods,
	}
}

// MarshalXML marshals the NETCONF XML data
func (m *RPCMessage) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	var buf bytes.Buffer
	for _, method := range m.Methods {
		buf.WriteString(method.MarshalMethod())
	}

	data := struct {
		MessageID string `xml:"message-id,attr"`
		Xmlns     string `xml:"xmlns,attr"`
		Methods   []byte `xml:",innerxml"`
	}{
		m.MessageID,
		"urn:ietf:params:xml:ns:netconf:base:1.0",
		buf.Bytes(),
	}

	// Wrap the raw XML (data) into <rpc>...</rpc> tags
	start.Name.Local = "rpc"
	return e.EncodeElement(data, start)
}

// RPCReply defines a reply to a RPC request
type RPCReply struct {
	XMLName   xml.Name   `xml:"rpc-reply"`
	Errors    []RPCError `xml:"rpc-error,omitempty"`
	Data      DataXML    `xml:"data,omitempty"`
	Ok        bool       `xml:",omitempty"`
	RawReply  string     `xml:"-"`
	MessageID string     `xml:"-"`
}

func NewRPCReply(rawXML []byte, ErrOnWarning bool, messageID string) (*RPCReply, error) {
	reply := &RPCReply{}
	reply.RawReply = string(rawXML)
	if strings.Contains(reply.RawReply, "<ok/>") {
		reply.Ok = true
	}

	//if err := xml.Unmarshal(reply.Data, )
	if err := xml.Unmarshal(rawXML, reply); err != nil {
		return nil, err
	}

	// will return a valid reply so setting Requests message id
	reply.MessageID = messageID

	if reply.Errors != nil {
		for _, rpcErr := range reply.Errors {
			if rpcErr.Severity == "error" || ErrOnWarning {
				return reply, &rpcErr
			}
		}
	}

	return reply, nil
}

// RPCError defines an error reply to a RPC request
type RPCError struct {
	Type     string `xml:"error-type"`
	Tag      string `xml:"error-tag"`
	Severity string `xml:"error-severity"`
	Path     string `xml:"error-path"`
	Message  string `xml:"error-message"`
	Info     string `xml:",innerxml"`
}

// Error generates a string representation of the provided RPC error
func (re *RPCError) Error() string {
	return fmt.Sprintf("netconf rpc [%s] '%s'", re.Severity, re.Message)
}

// RPCMethod defines the interface for creating an RPC method.
type RPCMethod interface {
	MarshalMethod() string 
}

// RawMethod defines how a raw text request will be responded to
type RawMethod string

// MarshalMethod converts the method's output into a string
func (r RawMethod) MarshalMethod() string {
	return string(r)
}

// MethodLock files a NETCONF lock target request with the remote host
func MethodLock(target string) RawMethod {
	return RawMethod(fmt.Sprintf("<lock><target><%s/></target></lock>", target))
}

// MethodUnlock files a NETCONF unlock target request with the remote host
func MethodUnlock(target string) RawMethod {
	return RawMethod(fmt.Sprintf("<unlock><target><%s/></target></unlock>", target))
}

// MethodGetConfig files a NETCONF get-config source request with the remote host
func MethodGetConfig(source string) RawMethod {
	return RawMethod(fmt.Sprintf("<get-config><source><%s/></source></get-config>", source))
}

// MethodCommit commit changes
func MethodCommit() RawMethod {
	return RawMethod("<commit/>")
}

// MethodDiscardChanges discard changes
func MethodDiscardChanges() RawMethod {
	return RawMethod("<discard-changes/>")
}

var msgID = uuid

// uuid generates a "good enough" uuid without adding external dependencies
func uuid() string {
	b := make([]byte, 16)
	io.ReadFull(rand.Reader, b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
