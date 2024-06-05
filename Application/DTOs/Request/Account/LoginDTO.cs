using System.ComponentModel.DataAnnotations;


namespace Application.DTOs.Request.Account
{
    public class LoginDTO
    {
        [EmailAddress, Required]
        [RegularExpression("[^@ \\t\\r\\n]+@[^@ \\t\\r\\n]+",
           ErrorMessage = "your email is not valid, provide valid email email such as" +
            " ...@gmail, @hotmail, @yahoo .com")]
        [Display(Name = "Email Address")]
        public string EmailAddress { get; set; } = string.Empty;


        [Required]
        [RegularExpression("^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[1-9])(?=.*?[#?!@$ %^&*-]).{8,}$",
            ErrorMessage = "Your password must be a mix Alphanumberic and special characters")]
        public string Password { get; set; } = string.Empty;
    }
}
