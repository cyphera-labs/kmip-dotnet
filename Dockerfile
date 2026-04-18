FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /app
COPY *.sln ./
COPY src/Cyphera.Kmip/Cyphera.Kmip.csproj src/Cyphera.Kmip/
COPY tests/Cyphera.Kmip.Tests/Cyphera.Kmip.Tests.csproj tests/Cyphera.Kmip.Tests/
RUN dotnet restore
COPY src/ src/
COPY tests/ tests/
RUN dotnet build --no-restore
CMD ["dotnet", "test", "--no-build", "--verbosity", "minimal"]
