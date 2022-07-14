package com.rudy.authenticationStatic;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;


public class AuthenticactionStaticTest {
	
	@ParameterizedTest
	@CsvSource({
		"Admin, Admin, CRUD, user authenticated successfully with permission: [CRUD]",
		"superA, superA, CRU, user authenticated successfully with permission: [CRU]",
		"superB, superB, CRD, user authenticated successfully with permission: [CRD]",
		"superC, superC, CUD, user authenticated successfully with permission: [CUD]",
		"superD, superD, RUD, user authenticated successfully with permission: [RUD]",
		"techA, techA, CR, user authenticated successfully with permission: [CR]",
		"techB, techB, CU, user authenticated successfully with permission: [CU]",
		"techC, techC, CD, user authenticated successfully with permission: [CD]",
		"techD, techD, RU, user authenticated successfully with permission: [RU]",
		"techE, techE, RD, user authenticated successfully with permission: [RD]",
		"techF, techF, UD, user authenticated successfully with permission: [UD]",
		"employeeA, employeeA, C, user authenticated successfully with permission: [C]",
		"employeeB, employeeB, R, user authenticated successfully with permission: [R]",
		"employeeC, employeeC, U, user authenticated successfully with permission: [U]",
		"employeeD, employeeD, D, user authenticated successfully with permission: [D]"
	}) 
	public void verifyAuthenticationFullPermissions(String usr, String pwd, String per,String expectResult) {
		MockedStatic <CredentialsStaticService> CredentialsMocked = Mockito.mockStatic(CredentialsStaticService.class);
		CredentialsMocked.when(()-> CredentialsStaticService.isValidCredential(usr, pwd)).thenReturn(true);
		
		MockedStatic <PermissionStaticService> PermissionMocked = Mockito.mockStatic(PermissionStaticService.class);
		PermissionMocked.when(()-> PermissionStaticService.getPermission(usr)).thenReturn(per);
		
		Authentication authentication = new Authentication();
		String actualResult = authentication.login(usr, pwd);
		
		Assertions.assertEquals(actualResult, expectResult, "ERROR! Verificación incorrecta");
		
		CredentialsMocked.close();
		PermissionMocked.close();
	}
	
	@Test
	public void verifyAuthenticationError(){
		String expectResult = "user or password incorrect";
		Authentication authentication = new Authentication();
		String actualResult = authentication.login("admin", "xxxxx");
		Assertions.assertEquals(actualResult, expectResult, "ERROR! Verificación incorrecta");
	}
}
