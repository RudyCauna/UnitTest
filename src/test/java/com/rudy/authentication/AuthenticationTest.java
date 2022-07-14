package com.rudy.authentication;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

public class AuthenticationTest {
	Authentication authentication;
	
	CredentialsService credentialsServiceMock = Mockito.mock(CredentialsService.class);
	PermissionService permissionServiceMock = Mockito.mock(PermissionService.class);
	
	@BeforeEach
	public void setup() {
		authentication = new Authentication();
		authentication.setCredentialsService(credentialsServiceMock);
		authentication.setPermissionService(permissionServiceMock);
	}
	
	@AfterEach
	public void cleanup() {
	}
	
	@Test
	public void verifyAuthenticationFullPermissions (){
		Mockito.when(credentialsServiceMock.isValidCredential("admin", "admin")).thenReturn(true);
		Mockito.when(permissionServiceMock.getPermission("admin")).thenReturn("CRUD");
		 
		String actualResult = authentication.login("admin", "admin");
		String expectResult = "user authenticated successfully with permission: [CRUD]";
		
		Assertions.assertEquals(actualResult, expectResult, "ERROR! Verificación incorrecta");
		
		Mockito.verify(credentialsServiceMock).isValidCredential("admin", "admin");
		Mockito.verify(permissionServiceMock).getPermission("admin");
	}
	
	
	@ParameterizedTest
	@CsvSource({
		"superA, superA, CRU, user authenticated successfully with permission: [CRU]",
		"superB, superB, CRD, user authenticated successfully with permission: [CRD]",
		"superC, superC, CUD, user authenticated successfully with permission: [CUD]",
		"superD, superD, RUD, user authenticated successfully with permission: [RUD]"
	}) 
	public void verifyAuthenticationTreePpermissions (String usr, String pwd, String per,String expectResult){ 
		Mockito.when(credentialsServiceMock.isValidCredential(usr, pwd)).thenReturn(true);
		Mockito.when(permissionServiceMock.getPermission(usr)).thenReturn(per);
			
		String actualResult = authentication.login(usr, pwd);
			
		Assertions.assertEquals(actualResult, expectResult, "ERROR! Verificación incorrecta");
			
		Mockito.verify(credentialsServiceMock).isValidCredential(usr, pwd);
		Mockito.verify(permissionServiceMock).getPermission(usr);
	}
	
	@ParameterizedTest
	@CsvSource({
		"techA, techA, CR, user authenticated successfully with permission: [CR]",
		"techB, techB, CU, user authenticated successfully with permission: [CU]",
		"techC, techC, CD, user authenticated successfully with permission: [CD]",
		"techD, techD, RU, user authenticated successfully with permission: [RU]",
		"techE, techE, RD, user authenticated successfully with permission: [RD]",
		"techF, techF, UD, user authenticated successfully with permission: [UD]"
	})  
	public void verifyAuthenticationTwoPermissions (String usr, String pwd, String per,String expectResult){
		Mockito.when(credentialsServiceMock.isValidCredential(usr, pwd)).thenReturn(true);
		Mockito.when(permissionServiceMock.getPermission(usr)).thenReturn(per);
		
		authentication.setCredentialsService(credentialsServiceMock);
		authentication.setPermissionService(permissionServiceMock);
		
		String actualResult = authentication.login(usr, pwd);
		
		Assertions.assertEquals(actualResult, expectResult, "ERROR! Verificación incorrecta");
		
		Mockito.verify(credentialsServiceMock).isValidCredential(usr, pwd);
		Mockito.verify(permissionServiceMock).getPermission(usr);
	}
	  
	@ParameterizedTest
	@CsvSource({
		"employeeA, employeeA, C, user authenticated successfully with permission: [C]",
		"employeeB, employeeB, R, user authenticated successfully with permission: [R]",
		"employeeC, employeeC, U, user authenticated successfully with permission: [U]",
		"employeeD, employeeD, D, user authenticated successfully with permission: [D]"
	})
	public void verifyAuthenticationOnePermission (String usr, String pwd, String per,String expectResult){ 
		Mockito.when(credentialsServiceMock.isValidCredential(usr, pwd)).thenReturn(true);
		Mockito.when(permissionServiceMock.getPermission(usr)).thenReturn(per);
			
		String actualResult = authentication.login(usr, pwd);
			
		Assertions.assertEquals(actualResult, expectResult, "ERROR! Verificación incorrecta");
			
		Mockito.verify(credentialsServiceMock).isValidCredential(usr, pwd);
		Mockito.verify(permissionServiceMock).getPermission(usr);
	  }
	
	@Test
	public void verifyAuthenticationError(){
		String expectResult = "user or password incorrect";
		String actualResult = authentication.login("admin", "xxxxx");
		Assertions.assertEquals(actualResult, expectResult, "ERROR! Verificación incorrecta");
	}
}