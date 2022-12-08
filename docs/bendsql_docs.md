## What is `bendsql`?
bendsql is a handy command line interface tool to work with Databend Cloud smoothly and efficiently as with a web browser. Use the tool as an alternative to manage your warehouses and stages, upload files, and run SQL queries.


## How to install bendsql

### brew install
If you're on MacOS, install bendsql using 'brew install':
```shell
brew tap databendcloud/homebrew-tap && brew install bendsql
```

### binary install
Go to [release](https://github.com/databendcloud/bendsql/releases/latest) and find a binary package for your platform.

### go install

```shell
go install github.com/databendcloud/bendsql/cmd/bendsql@latest
```

## Work with bendsql

### Sign in to bendsql

```shell
bendsql login
```

![](https://tva3.sinaimg.cn/large/005UfcOkly8h78cbw42jcj30z80b0aat.jpg)

If you don't have an account yet, create one in Databend Cloud.
Signing into bendsql requires your organization's information. You can press Enter to select the default organization during the sign-in process and then change it afterwards with the command ` bendsql configure --org <your_org> `.

### Manage Warehouses

bendsql provides a bunch of commands to work with warehouses in Databend Cloud.

```shell
USAGE
  bendsql warehouse cmd [flags]
CORE COMMANDS
  create:      Create a warehouse
  delete:      Delete a warehouse
  ls:          show warehouse list
  resume:      Resume a warehouse
  status:      show warehouse status
  suspend:     Suspend a warehouse
INHERITED FLAGS
  --help   Show help for command
LEARN MORE
  Use 'bendsql <command> <subcommand> --help' for more information about a command.
```

### Manage Stages

`bendsql` allows you to upload files to a stage and view the details of the staged files.

```shell
Operate stage
USAGE
  bendsql stage <command> [flags]
CORE COMMANDS
  ls:          List stage or files in stage
  upload:      Upload file to stage using warehouse
INHERITED FLAGS
  --help   Show help for command
LEARN MORE
  Use 'bendsql <command> <subcommand> --help' for more information about a command.
```

![](https://tva2.sinaimg.cn/large/005UfcOkly8h78cduok6uj30zk04yaay.jpg)

### Run SQL Queries
You can even run SQL queries with bendsql. Specify a large warehouse for queries that need more computing resources.

```shell
bendsql query YOURSQL --warehouse YOURWAREHOUSAE
```

To make you more productive with bendsql, we're improving the command `bendsql query` to provide an interactive and user-friendly experience for SQL queries.

### Do More with bendsql

Type `bendsql -h` and discover more useful commands to make your work easier. 
