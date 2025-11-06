To build the project simply clone this repository and install the EntityFramework driver you'd like to use(in my case npgsql for postgresql)
register it in Program.cs (builder.Services.UseNpgsql() to your driver of choice) 
then change the connection string in appsettings.json aswell as the jwt properties(not needed but since this is a public repository it's better to change it to use your secret key aswell as issuer and audience)
if you don't have dotnet-ef install the tool
run dotnet tool install --global dotnet-ef in powershell to install it
then to apply the migrations navigate to the root of the project and simply run
dotnet ef database update (if the connection to the database is established you'll get a build success message) 

this project is meant to give a prebuilt minimal template to start from since i noticed that jwt auth is pretty boilerplatey when starting new small webapis. 
