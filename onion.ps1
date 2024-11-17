function onion {
    # get project dir name
    $project_name = Get-Item -Path "." -Force | Select-Object -ExpandProperty Name

    # create solution
    dotnet new sln -n ${project_name}

    # create layers
    dotnet new classlib -n "$project_name.Domain"
    dotnet new classlib -n "$project_name.Application"
    dotnet new classlib -n "$project_name.Infrastructure"
    dotnet new webapi -n "$project_name.API"

    # add projects to solution
    dotnet sln add "$project_name.Domain"
    dotnet sln add "$project_name.Application"
    dotnet sln add "$project_name.Infrastructure"
    dotnet sln add "$project_name.API"

    # delete default class files
    Remove-Item "$project_name.Domain/Class1.cs"
    Remove-Item "$project_name.Application/Class1.cs"
    Remove-Item "$project_name.Infrastructure/Class1.cs"

    # add project references and download dependencies
    Set-Location "$project_name.Domain"
    dotnet add package Microsoft.AspNetCore.Identity
    dotnet add package Microsoft.AspNetCore.Identity.EntityframeworkCore

    Set-Location "../$project_name.Application"
    dotnet add reference "../$project_name.Domain"

    Set-Location "../$project_name.Infrastructure"
    dotnet add reference "../$project_name.Domain"
    dotnet add package Microsoft.EntityFrameworkCore.SqlServer
    dotnet add package Microsoft.EntityFrameworkCore.Design

    Set-Location "../$project_name.API"
    dotnet add reference "../$project_name.Application"
    dotnet add reference "../$project_name.Infrastructure"
    dotnet add package Microsoft.EntityFrameworkCore.Tools
    # dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer

    Set-Location ..

    # domain layer default files content
    New-Item -ItemType Directory -Path "$project_name.Domain/Abstractions"
    New-Item -ItemType Directory -Path "$project_name.Domain/Models"
    New-Item -ItemType Directory -Path "$project_name.Domain/Interfaces"
    New-Item -ItemType Directory -Path "$project_name.Domain/Specifications"

    Set-Content -Path "$project_name.Domain/Abstractions/BaseModel.cs" -Value @"
namespace $project_name.Domain.Abstractions;


public abstract class BaseModel
{
    public Guid Id { get; private set; }
}
"@

    Set-Content -Path "$project_name.Domain/Abstractions/TimeStampedBaseEntity.cs" -Value @"
namespace $project_name.Domain.Abstractions;

public abstract class TimeStampedModel : BaseModel
{
    public DateTime CreatedAt { get; } = DateTime.UtcNow;
}

public abstract class ExtendedTimeStampedModel : TimeStampedModel
{
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}
"@

    Set-Content -Path "$project_name.Domain/Specifications/Specification.cs" -Value @"
using System.Linq.Expressions;
using $project_name.Domain.Abstractions;

namespace $project_name.Domain.Specifications;

public abstract class Specification<TModel> where TModel : BaseModel
{
    public Expression<Func<TModel, bool>>? Criteria { get; }
    public List<Expression<Func<TModel, object>>>? Includes { get; } = new();
    public Expression<Func<TModel, object>>? OrderBy { get; set; }

    public Specification()
    {

    }

    public Specification(Expression<Func<TModel, bool>> criteria)
    {
        Criteria = criteria;
    }
}

public abstract class Specification<TModel, TResult> : Specification<TModel> where TModel : BaseModel
{
    public Specification(Expression<Func<TModel, bool>> criteria) : base(criteria) { }
    public Expression<Func<TModel, TResult>>? Selector { get; set; }
}
"@

    Set-Content -Path "$project_name.Domain/Specifications/SpecificationQueryBuilder.cs" -Value @"
using System.Linq.Expressions;
using Microsoft.EntityFrameworkCore;
using $project_name.Domain.Abstractions;

namespace $project_name.Domain.Specifications;

public static class SpecificationQueryBuilder
{
    public static IQueryable<TModel> Build<TModel>(IQueryable<TModel> queryable, Specification<TModel> specification)
    where TModel : BaseModel
    {
        if(specification.Criteria is not null)
            queryable = queryable.Where(specification.Criteria);

        if(specification.Includes is not null)
            foreach(Expression<Func<TModel, object>> include in specification.Includes)
                queryable = queryable.Include(include);

        if(specification.OrderBy is not null)
            queryable = queryable.OrderBy(specification.OrderBy);

        return queryable;
    }

    public static IQueryable<TResult> Build<TModel, TResult>(IQueryable<TModel> queryable, Specification<TModel, TResult> specification)
    where TModel : BaseModel =>
        Build<TModel>(queryable, specification).Select(specification.Selector!);
}
"@

    Set-Content -Path "$project_name.Domain/Interfaces/IRepository.cs" -Value @"
using System.Linq.Expressions;
using $project_name.Domain.Abstractions;

namespace $project_name.Domain.Interfaces;

public interface IRepository<TModel> where TModel : BaseModel
{
    Task<IEnumerable<TModel>> GetAll();
    Task<IEnumerable<TModel>> GetAll(Specification<TModel> specification);
    Task<IEnumerable<TResult>> GetAll<TResult>(Specification<TModel, TResult> specification);
    Task<TModel?> GetOne(Specification<TModel> specification);
    Task<TResult?> GetOne<TResult>(Specification<TModel, TResult> specification);
    Task<TModel> Add(TModel model);
    TModel Update(TModel model);
    void Delete(TModel model);
}
"@

    Set-Content -Path "$project_name.Domain/Interfaces/IRepositoryManager.cs" -Value @"
namespace $project_name.Domain.Interfaces;

public interface IRepositoryManager : IDisposable
{
    Task Save();
}
"@

    Set-Content -Path "$project_name.Domain/Models/User.cs" -Value @"
using Microsoft.AspNetCore.Identity;
using $project_name.Domain.Abstractions;

namespace $project_name.Domain.Models;

public class User : IdentityUser<Guid>
{
    public DateTime CreatedAt { get; set; }
}
"@

    # application layer default files content
    New-Item -ItemType Directory -Path "$project_name.Application/DTOs"
    New-Item -ItemType Directory -Path "$project_name.Application/Mappers"
    New-Item -ItemType Directory -Path "$project_name.Application/Responses"
    New-Item -ItemType Directory -Path "$project_name.Application/Interfaces"
    New-Item -ItemType Directory -Path "$project_name.Application/Services"
    New-Item -ItemType Directory -Path "$project_name.Application/Utilities"

    Set-Content -Path "$project_name.Application/Responses/BaseResponse.cs" -Value @"
namespace $project_name.Application.Responses;

public abstract record BaseResponse(int StatusCode);
"@

    Set-Content -Path "$project_name.Application/Responses/OkResponse.cs" -Value @"
namespace $project_name.Application.Responses;

public record OkResponse<TResult>(TResult Result) : BaseResponse(200);
"@

    Set-Content -Path "$project_name.Application/Responses/CreatedResponse.cs" -Value @"
namespace $project_name.Application.Responses;

public record CreatedResponse<TResult> : OkResponse<TResult>
{
    public CreatedResponse(TResult Data) : base(Data) => this.StatusCode = 201;
}
"@

    Set-Content -Path "$project_name.Application/Responses/NotFoundResponse.cs" -Value @"
namespace $project_name.Application.Responses;

public record NotFoundResponse : BaseResponse
{
    public string Message {get;}
    public NotFoundResponse(object id, string resource, string idField = "Id") : base(404) =>
        Message = $"{resource} with {idField} {id} Not Found";
}
"@

    Set-Content -Path "$project_name.Application/Responses/NoContentResponse.cs" -Value @"
namespace $project_name.Application.Responses;

public record NoContentResponse() : BaseResponse(204);
"@

    Set-Content -Path "$project_name.Application/Responses/UnauthorizedResponse.cs" -Value @"
namespace $project_name.Application.Responses;

public record UnAuthorizedResponse(string Message = "Email or password is incorrect") : BaseResponse(401);
"@

    Set-Content -Path "$project_name.Application/Responses/ForbiddenResponse.cs" -Value @"
namespace $project_name.Application.Responses;

public record ForbiddenResponse(string Message = "Permission denied") : BaseResponse(403);
"@

    Set-Content -Path "$project_name.Application/Responses/BadRequestResponse.cs" -Value @"
namespace $project_name.Application.Responses;

public record BadRequestResponse(string Message) : BaseResponse(400);
"@

    Set-Content -Path "$project_name.Application/Responses/InternalServerErrorResponse.cs" -Value @"
namespace $project_name.Application.Responses;

public record InternalServerErrorResponse(string Message = "Something went wrong") : BaseResponse(500);
"@

    Set-Content -Path "$project_name.Application/Interfaces/IService.cs" -Value @"
using $project_name.Application.Responses;

namespace $project_name.Application.Interfaces;

public interface IService<TCreateDTO, TUpdateDTO>
{
    Task<BaseResponse> GetAll();
    Task<BaseResponse> GetById(Guid id);
    Task<BaseResponse> Create(TCreateDTO createDTO);
    Task<BaseResponse> Update(Guid id, TUpdateDTO updateDTO);
    Task<BaseResponse> Delete(Guid id);
}
"@

    Set-Content -Path "$project_name.Application/Utilities/ListExtensions.cs" -Value @"
namespace $project_name.Application.Utilities;

public static class IEnumerableExtensions
{
    public static IEnumerable<Destination> ConvertAll<Destination, Source>(
        this IEnumerable<Source> source,
        Func<Source, Destination> convertFunc
    )
    {
        if (source == null) throw new ArgumentNullException(nameof(source));
        if (convertFunc == null) throw new ArgumentNullException(nameof(convertFunc));
        return source.Select(convertFunc).ToList();
    }
}
"@

    Set-Content -Path "$project_name.Application/Utilities/DependencyInjection.cs" -Value @"
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace $project_name.Application.Utilities;

public static class DependencyInjection
{
    /// <summary>
    ///     Inject all the services
    /// </summary>
    /// <param name="services">IServiceCollection</param>
    /// <returns>A reference to this instance after injecting services</returns>
    public static IServiceCollection AddServices(this IServiceCollection services)
    {
        return services;
    }
}
"@

    # infrastructure layer default files content
    New-Item -ItemType Directory -Path "$project_name.Infrastructure/Data"
    New-Item -ItemType Directory -Path "$project_name.Infrastructure/Data/Configuration"
    New-Item -ItemType Directory -Path "$project_name.Infrastructure/Repositories"
    New-Item -ItemType Directory -Path "$project_name.Infrastructure/Utilities"

    Set-Content -Path "$project_name.Infrastructure/Data/ApplicationDbContext.cs" -Value @"
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using $project_name.Domain.Models;

namespace $project_name.Infrastructure.Data;

public sealed class ApplicationDbContext: IdentityDbContext<User, IdentityRole<Guid>, Guid>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
    : base(options){}

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(ApplicationDbContext).Assembly);
    }
}
"@

    Set-Content -Path "$project_name.Infrastructure/Repositories/GenericRepository.cs" -Value @"
using Microsoft.EntityFrameworkCore;
using $project_name.Domain.Interfaces;
using $project_name.Domain.Abstractions;
using $project_name.Domain.Specifications;
using $project_name.Infrastructure.Data;

namespace $project_name.Infrastructure.Repositories;

public class GenericRepository<TModel> : IRepository<TModel> where TModel : BaseModel
{
    protected readonly ApplicationDbContext _context;
    protected readonly DbSet<TModel> _dbSet;
    public GenericRepository(ApplicationDbContext context)
    {
        _context = context;
        _dbSet = _context.Set<TModel>();
    }

    public async virtual Task<IEnumerable<TModel>> GetAll() =>
        await _dbSet.ToListAsync();

    public async Task<IEnumerable<TModel>> GetAll(Specification<TModel> specification) =>
        await SpecificationQueryBuilder.Build(_dbSet, specification).ToListAsync();

    public async Task<IEnumerable<TResult>> GetAll<TResult>(Specification<TModel, TResult> specification) =>
        await SpecificationQueryBuilder.Build(_dbSet, specification).ToListAsync();

    public async Task<TModel?> GetOne(Specification<TModel> specification) =>
        await SpecificationQueryBuilder.Build(_dbSet, specification).FirstOrDefaultAsync();

    public async Task<TResult?> GetOne<TResult>(Specification<TModel, TResult> specification) =>
        await SpecificationQueryBuilder.Build(_dbSet, specification).FirstOrDefaultAsync();

    public async virtual Task<TModel?> GetById(Guid id) =>
        await _dbSet.FindAsync(id);

    public async virtual Task<TModel> Add(TModel model) =>
        (await _dbSet.AddAsync(model)).Entity;

    public virtual TModel Update(TModel model) =>
        _dbSet.Update(model).Entity;

    public virtual void Delete(TModel model) =>
        _dbSet.Remove(model);
}
"@

    Set-Content -Path "$project_name.Infrastructure/Repositories/RepositoryManager.cs" -Value @"
using Microsoft.Extensions.DependencyInjection;
using $project_name.Domain.Interfaces;
using $project_name.Infrastructure.Data;

namespace $project_name.Infrastructure.Repositories;

public class RepositoryManager : IRepositoryManager
{
    private readonly ApplicationDbContext _context;
    private IServiceProvider _serviceProvider;
    public RepositoryManager(ApplicationDbContext context, IServiceProvider serviceProvider)
    {
        _context = context;
        _serviceProvider = serviceProvider;
    }
    public async void Dispose() => await _context.DisposeAsync();
    public async Task Save() => await _context.SaveChangesAsync();
}
"@

    Set-Content -Path "$project_name.Infrastructure/Utilities/DependencyInjection.cs" -Value @"
using Microsoft.Extensions.DependencyInjection;
using $project_name.Domain.Interfaces;
using $project_name.Infrastructure.Repositories;

namespace $project_name.Infrastructure.Utilities;

public static class DependencyInjection
{
    /// <summary>
    ///     Inject all the repositories
    /// </summary>
    /// <param name="services">IServiceCollection</param>
    /// <returns>A reference to this instance after injecting repositories</returns>
    public static IServiceCollection AddRepositories(this IServiceCollection services)
    {
        services.AddScoped<IRepositoryManager, RepositoryManager>();
        services.AddScoped(typeof(IRepository<>), typeof(GenericRepository<>));
        return services;
    }
}
"@

    Set-Content -Path "$project_name.Infrastructure/Data/Configuration/UserConfiguration.cs" -Value @"
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using $project_name.Domain.Models;

namespace $project_name.Infrastructure.Data.Configuration;


public class UserConfiguration : IEntityTypeConfiguration<User>
{
    public void Configure(EntityTypeBuilder<User> builder)
    {
        builder.HasKey(user => user.Id);
    }
}
"@

    # presentation layer default files content
    New-Item -ItemType Directory -Path "$project_name.API/Controllers"
    New-Item -ItemType Directory -Path "$project_name.API/Utilities"

    Set-Content -Path "$project_name.API/Controllers/GenericController.cs" -Value @"
using Microsoft.AspNetCore.Mvc;
using $project_name.Application.Responses;
using $project_name.Application.Interfaces;
using $project_name.Presentation.Utilities;

namespace $project_name.Presentation.Controllers;

[Route("Api/[controller]")]
public abstract class GenericController<TCreateDTO, TUpdateDTO, TResponseDTO> : ControllerBase
{
    protected readonly IService<TCreateDTO, TUpdateDTO> _service;

    public GenericController(IService<TCreateDTO, TUpdateDTO> service) =>
        _service = service;

    [HttpGet]
    public async virtual Task<IActionResult> Get() =>
        Ok(
            (await _service.GetAll())
            .GetResult<IEnumerable<TResponseDTO>>()
        );

    [HttpGet("{id}")]
    public async virtual Task<IActionResult> Get(Guid id)
    {
        BaseResponse response = await _service.GetById(id);
        return response.StatusCode == 200 ? Ok(response.GetResult<TResponseDTO>()) : ProcessError(response);
    }

    [HttpPost]
    public async virtual Task<IActionResult> Create(TCreateDTO createDTO)
    {
        BaseResponse response = await _service.Create(createDTO);
        if(response.StatusCode != 201) return ProcessError(response);
        var result = response.GetResult<TResponseDTO>();
        int index = this.GetType().ToString().Split('.').Last().IndexOf("Controller");
        string path = this.GetType().ToString().Split('.').Last().Remove(index);
        return Created($"/api/{path}/{result!.GetType().GetProperty("Id")!.GetValue(result)}", result);
    }

    [HttpPut]
    public async virtual Task<IActionResult> Update(Guid Id, TUpdateDTO updateDTO)
    {
        BaseResponse response = await _service.Update(Id, updateDTO);
        int index = this.GetType().ToString().Split('.').Last().IndexOf("Controller");
        string path = this.GetType().ToString().Split('.').Last().Remove(index);
        return response.StatusCode switch
        {
            201 => Created($"/api/{path}/{Id}", response.GetResult<TResponseDTO>()),
            _ => ProcessError(response)
        };
    }

    [HttpDelete("{id}")]
    public async virtual Task<IActionResult> Delete(Guid id)
    {
        BaseResponse response = await _service.Delete(id);
        return response.StatusCode == 204 ? NoContent() : ProcessError(response);
    }

    protected IActionResult ProcessError(BaseResponse response)
    {
        return response.StatusCode switch
        {
            400 => BadRequest((BadRequestResponse)response),
            401 => Unauthorized((UnAuthorizedResponse)response),
            403 => Forbid(((ForbiddenResponse)response).Message),
            404 => NotFound((NotFoundResponse)response),
            500 => StatusCode(response.StatusCode, ((InternalServerErrorResponse)response).Message),
            _ => throw new NotImplementedException()
        };
    }
}
"@

    Set-Content -Path "$project_name.API/Utilities/ResponseExtensions.cs" -Value @"
using $project_name.Application.Responses;

namespace $project_name.Presentation.Utilities;

public static class ResponseExtensions
{
    public static TResultType GetResult<TResultType>(this BaseResponse response) =>
        ((OkResponse<TResultType>)response).Result;
}
"@

    Set-Content -Path "$project_name.API/Utilities/ServiceExtensions.cs" -Value @"
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
// using Microsoft.AspNetCore.Authentication.JwtBearer;
// using Microsoft.IdentityModel.Tokens;
using $project_name.Domain.Models;
using $project_name.Application.Utilities;
using $project_name.Infrastructure.Utilities;
using $project_name.Infrastructure.Data;

namespace $project_name.Presentation.Utilities;

public static class ServiceExtensions
{
    public static IServiceCollection Configure(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddEndpointsApiExplorer();
        services.AddSwaggerGen();
        services.AddDbContextPoolConfiguration(configuration);
        services.AddIdentityConfiguration(configuration);
        services.AddAuthentication();
        services.AddAuthorization();
        // uncomment if want to use jwt
        // DO NOT FORGET TO ADD JWT SETTINGS TO USER SECRETS
        // services.AddJWTAuthentication(configuration);
        services.AddCorsConfiguration();
        services.AddIISIntegrationConfiguration();
        services.AddControllers();
        services.AddServices();
        services.AddRepositories();
        return services;
    }

    public static IServiceCollection AddDbContextPoolConfiguration(this IServiceCollection services, IConfiguration configuration) =>
        services.AddDbContextPool<ApplicationDbContext>(
            options => options.UseSqlServer(configuration.GetConnectionString("DefaultConnection"))
        );

    public static IServiceCollection AddIdentityConfiguration(this IServiceCollection services, IConfiguration configuration)
    {
        /* ------- Register Identity ------- */
        services.AddIdentity<User, IdentityRole<Guid>>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();
        /* ------- Get Default User Data from appsettings.json ------- */
        var defaultUserModel = configuration.GetSection("DefaultUserModel");
        if (defaultUserModel.Exists())
            services.Configure<User>(defaultUserModel);
        return services;
    }

    // public static IServiceCollection AddJWTAuthentication(this IServiceCollection services, IConfiguration configuration)
    // {
    //     var jwtSettings = configuration.GetSection("JwtSettings");
    //     services.AddAuthentication(options =>
    //     {
    //         options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    //         options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    //     })
    //     .AddJwtBearer(options =>
    //     {
    //         options.TokenValidationParameters = new TokenValidationParameters
    //         {
    //             ValidateIssuer = true,
    //             ValidateAudience = true,
    //             ValidateLifetime = true,
    //             ValidateIssuerSigningKey = true,
    //             ValidIssuer = jwtSettings["Issuer"],
    //             ValidAudience = jwtSettings["Audience"],
    //             IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["SecretKey"]!))
    //         };
    //     });
    //     return services;
    // }

    public static IServiceCollection AddCorsConfiguration(this IServiceCollection services) =>
        services.AddCors(options =>
            {
                options.AddPolicy(
                    "CorsPolicy",
                    builder => builder.AllowAnyOrigin()
                                      .AllowAnyMethod()
                                      .AllowAnyHeader()
                );
            }
        );

    public static IServiceCollection AddIISIntegrationConfiguration(this IServiceCollection services) =>
        services.Configure<IISOptions>(options => {});
}
"@

    Set-Content -Path "$project_name.API/Utilities/WebApplicationExtensions.cs" -Value @"
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using $project_name.Domain.Models;

namespace $project_name.Presentation.Utilities;

public static class WebAppExtensions
{
    public static void Configure(this WebApplication app)
    {
        app.UseHttpsRedirection();
        app.UseAuthentication();
        app.UseCors("CorsPolicy");
        app.UseAuthorization();
        app.MapControllers();
        if (app.Environment.IsDevelopment())
        {
            app.UseSwagger();
            app.UseSwaggerUI();
        }
        app.Lifetime.ApplicationStarted.Register(async () => await app.PreLoadDefaultData());
    }

    private static async Task PreLoadDefaultData(this WebApplication app)
    {
        using var scope = app.Services.CreateAsyncScope();
        /* ------- Load Default Roles ------- */
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole<Guid>>>();
        await roleManager.CreateRolesIfNotExist(["User", "Admin"]);
        /* ------- Load Default User ------- */
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<User>>();
        User? user = scope.ServiceProvider.GetService<IOptions<User>>()?.Value;
        if(user is not null) await userManager.CreateUserIfNotExist(user, "Admin");
    }

    private static async Task CreateUserIfNotExist(this UserManager<User> userManager, User user, string role)
    {
        User? existingUser = await userManager.FindByIdAsync(user.Id.ToString());
        if(existingUser is not null) return;
        var result = await userManager.CreateAsync(user);
        if(!result.Succeeded)
        {
            foreach(var e in result.Errors) Console.WriteLine(e.Description);
        }
        await userManager.AddToRoleAsync(user, role);
    }

    private static async Task CreateRolesIfNotExist(this RoleManager<IdentityRole<Guid>> roleManager, string[] roles)
    {
        foreach(string role in roles)
        {
            if(await roleManager.RoleExistsAsync(role)) continue;
            var result = await roleManager.CreateAsync(new IdentityRole<Guid>(role));
            if(result.Succeeded) continue;
            foreach(var e in result.Errors) Console.WriteLine(e.Description);
        }
    }
}
"@

    Set-Content -Path "$project_name.API/Program.cs" -Value @"
using $project_name.Presentation.Utilities;

var builder = WebApplication.CreateBuilder(args);

if(builder.Environment.IsDevelopment())
{
    builder.Configuration.AddUserSecrets<Program>();
}
builder.Services.Configure(builder.Configuration);

var app = builder.Build();
app.Configure();

app.Run();
"@

    # initiate user secrets and add default sections
    Set-Location "$project_name.API"
    dotnet user-secrets init
    dotnet user-secrets set "ConnectionStrings__DefaultConnection" "Server=localhost; Database=${project_name}_DB; Trusted_Connection=True; TrustServerCertificate=True;"
    Set-Location ..

    dotnet new gitignore
}
