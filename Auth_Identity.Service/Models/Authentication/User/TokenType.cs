﻿namespace Auth_Identity.Service.Models.Authentication.User;

public class TokenType
{
    public string Token { get; set; }
    public DateTime ExpiryTokenDate { get; set; }
}
