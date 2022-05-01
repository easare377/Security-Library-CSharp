using System;
using Konect.Security;
using Xunit;

namespace SecurityUtil.Test;

public class PasswordSecurityTest
{
    [Fact]
    public void IsValidAuthKey_Returns_True()
    {
        int iterations = 100;
        for (int i = 0; i < iterations; i++)
        {
            var authData = new {name = "Emmanuel Asare", date = DateTime.Now};
            string key = PasswordSecurity.GenerateRandomPassword(20);
            string authKey = PasswordSecurity.GenerateAuthKey(key, authData);
            bool isAuth = PasswordSecurity.IsValidAuthKey(authKey, key);
            Assert.True(isAuth);
        }
    }
}