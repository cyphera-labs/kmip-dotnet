FROM mcr.microsoft.com/dotnet/sdk:8.0
WORKDIR /app
COPY . .
RUN dotnet build
CMD ["dotnet", "test", "--no-build", "--verbosity", "minimal"]
