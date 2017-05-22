package okta

//func TestParseSAML(t *testing.T) {
//	var samlResponse saml.Response
//	data, err := ioutil.ReadFile("testdata/duo.saml")
//	if err != nil {
//		t.Fatalf("Error reading duo.saml : %s", err)
//	}
//
//	resp, err := ParseSAML(data)
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	err = xml.Unmarshal(resp, &samlResponse)
//	for _, a := range samlResponse.Assertion.AttributeStatement.Attributes {
//		if strings.HasSuffix(a.Name, "SAML/Attributes/Role") {
//			fmt.Printf("%s, %s\n", a.XMLName, a.Name)
//			for _, v := range a.AttributeValues {
//				fmt.Printf("%s\n", v.Value)
//			}
//		}
//	}
//}

//func TestGetRolesFromSAML(t *testing.T) {
//	var samlResponse saml.Response
//	data, err := ioutil.ReadFile("testdata/duo.saml")
//	if err != nil {
//		t.Fatalf("Error reading duo.saml : %s", err)
//	}
//
//	err = ParseSAML(data, &samlResponse)
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	roles, err := GetRolesFromSAML(samlResponse)
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	fmt.Printf("%v\n", roles)
//}
