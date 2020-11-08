using System;
using System.Data;
using System.Data.SqlClient;
using System.Text;
using Identity.Dapper;
using Identity.Dapper.Models;
using Identity.Dapper.SqlServer.Connections;
using Identity.Dapper.SqlServer.Models;
using IdentityAndJwtExample.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

namespace IdentityAndJwtExample
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();
            services.AddAuthorization();

            #region Dapper.Identity Configurations
            services.ConfigureDapperConnectionProvider<SqlServerConnectionProvider>(Configuration.GetSection("DapperIdentity")) //Identity connection ayarı.
                    .ConfigureDapperIdentityCryptography(Configuration.GetSection("DapperIdentityCryptography")) //Identity kriptografi ayarı.
                    .ConfigureDapperIdentityOptions(new DapperIdentityOptions { UseTransactionalBehavior = false }); //Transaction işlemlerini tüm işlemlerde kullanmak için true yap.

            services.AddIdentity<AppUser, AppRole>(x =>
            {
                //Kullanıcı adında geçerli olan karakterleri belirtiyoruz.
                x.User.AllowedUserNameCharacters = "abcçdefghiıjklmnoöpqrsştuüvwxyzABCÇDEFGHIİJKLMNOÖPQRSŞTUÜVWXYZ0123456789-._@+";
                x.Password.RequireDigit = false; //0-9 arası sayısal karakter zorunluluğunu kaldırıyoruz.
                x.Password.RequiredLength = 1; //En az kaç karakterli olması gerektiğini belirtiyoruz.
                x.Password.RequireLowercase = false; //Küçük harf zorunluluğunu kaldırıyoruz.
                x.Password.RequireNonAlphanumeric = false; //Alfanumerik zorunluluğunu kaldırıyoruz.
                x.Password.RequireUppercase = false; //Büyük harf zorunluluğunu kaldırıyoruz.
            })
                    .AddDapperIdentityFor<SqlServerConfiguration>()
                    .AddDefaultTokenProviders();

            services.ConfigureApplicationCookie(opt =>
            {
                opt.AccessDeniedPath = new PathString("/yetkisiz-sayfa"); //Yetkisiz kullanıcı'nın göreceği sayfa.
                opt.LoginPath = new PathString("/Giris-Yap"); //Login giriş sayfası.
                opt.Cookie.Name = "AspNetCoreIdentity"; //Oluşturulacak Cookie'yi isimlendiriyoruz.
                opt.Cookie.HttpOnly = true; //Kötü niyetli insanların client-side tarafından Cookie'ye erişmesini engelliyoruz.
                opt.Cookie.SameSite = SameSiteMode.Strict; //Dış kaynakların Cookie'yi kullanmasını engelliyoruz.
                opt.ExpireTimeSpan = TimeSpan.FromMinutes(30); //CookieBuilder nesnesinde tanımlanan Expiration değerinin varsayılan değerlerle ezilme ihtimaline karşın tekrardan Cookie vadesini burada da belirtiliyor.
                opt.SlidingExpiration = true; //Expiration süresinin yarısı kadar süre zarfında istekte bulunulursa eğer geri kalan yarısını tekrar sıfırlayarak ilk ayarlanan süreyi tazeleyecektir.
            });
            #endregion

            #region JWT Configurations
            services.AddAuthentication(o=> {
                //Kullanıcı silindikten sonra ilgili cookie'yi siliyoruz.
                o.DefaultAuthenticateScheme = IdentityConstants.ApplicationScheme;
                o.DefaultChallengeScheme = IdentityConstants.ApplicationScheme;
                o.DefaultSignInScheme = IdentityConstants.ExternalScheme;

                o.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                o.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(option =>
            {
                option.SaveToken = true;
                option.RequireHttpsMetadata = false;
                option.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateAudience = true, //'ValidateAudience' ile token üzerinde Audience doğrulamasını aktifleştirdik
                    ValidateIssuer = true, //'ValidateIssuer' ile token üzerinde Issuer doğrulamasını aktifleştirdik.
                    ValidateLifetime = true, //'ValidateLifetime' ile token değerinin kullanım süresi doğrulamasını aktifleştirdik.
                    ValidateIssuerSigningKey = true, //'ValidateIssuerSigningKey' ile token değerinin bu uygulamaya ait olup olmadığını anlamamızı sağlayan Security Key doğrulamasını aktifleştirdik.
                    ValidIssuer = Configuration["Token:Issuer"], //'ValidIssuer' ile uygulamadaki tokenın Issuer değerini belirledik.
                    ValidAudience = Configuration["Token:Audience"], //'ValidAudience' ile uygulamadaki tokenın Audience değerini belirledik.
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["Token:SecurityKey"])), //'IssuerSigningKey' ile Security Key doğrulaması için SymmetricSecurityKey nesnesi aracılığıyla mevcut keyi belirtiyoruz.
                    ClockSkew = TimeSpan.Zero // 'ClockSkew' ile TimeSpan.Zero değeri ile token süresinin üzerine ekstra bir zaman eklemeksizin sıfır değerini belirtiyoruz.
                };
            });
            #endregion

            #region Swagger Configurations
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "IdentityAndJwtExample Api", Version = "V0.1" });
                c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    In = ParameterLocation.Header,
                    Description = "Please insert JWT with Bearer into field",
                    Name = "Authorization",
                    Type = SecuritySchemeType.ApiKey
                });
                c.AddSecurityRequirement(new OpenApiSecurityRequirement {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = "Bearer"
                            }
                        },
                        new string[] { }
                    }
                });
            });
            #endregion

            //Singleton yapıda SqlConnection nesnesini register ediyoruz.
            services.AddSingleton<IDbConnection>((sp) => new SqlConnection(Configuration["DapperIdentity:ConnectionString"].ToString()));
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseSwagger();
            app.UseSwaggerUI(c => { c.SwaggerEndpoint("/swagger/v1/swagger.json", "Swagger"); });

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
