using Login;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Login.Model;
using System.Reflection.Metadata;
using System.Text;
using NLog.Web;
using Microsoft.Extensions.Configuration;
using IHostingEnvironment = Microsoft.AspNetCore.Hosting.IHostingEnvironment;

var builder = WebApplication.CreateBuilder(args);
//var logger = NLogBuilder.ConfigureNLog("nlog.config").GetCurrentClassLogger();

//var logger = NLog.LogManager.LoadConfiguration("nlog.config").GetCurrentClassLogger();

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddDbContext<LoginDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));


builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAngularApp",
        policy =>
        {
            policy.WithOrigins("http://localhost:4200")
                  .AllowAnyMethod()
                  .AllowAnyHeader();
        });
});



void Configure(IApplicationBuilder app, IHostingEnvironment env)
{
    app.UseCors(builder =>
        builder.WithOrigins("http://localhost:4200")
               .AllowAnyHeader()
               .AllowAnyMethod());
    // Other configurations
    app.UseCors("AllowAngularApp");
}




builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(
        policy =>
        {
            policy.AllowAnyOrigin()
            .AllowAnyMethod()
            .AllowAnyHeader();
        });
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseCors();
app.UseHttpsRedirection();

app.UseCors("AllowAngularApp");
app.UseAuthorization();

app.MapControllers();

app.Run();

