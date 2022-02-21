package auth

const qryCreateTable = "CREATE TABLE IF NOT EXISTS Users (" +
	"PK_USER TEXT NOT NULL PRIMARY KEY UNIQUE," +
	"Password TEXT NOT NULL," +
	"Email TEXT," +
	"Salt TEXT NOT NULL," +
	"Session_id TEXT," +
	"Session_exp BIGINT," +
	"Auth_level INTEGER DEFAULT 0" +
	");"

const qryNewUser = "INSERT INTO Users (PK_USER, Password, Email, Salt, Auth_level) VALUES (?,?,?,?,?);"

const qryNewSession = "UPDATE Users SET Session_id = ?, Session_exp = ? WHERE PK_USER = ?;"

const qryGetUserSession = "SELECT PK_USER,Session_exp,Auth_level FROM Users WHERE Session_id = ?;"

const qryGetUser = "SELECT Password, Email, Salt, Auth_level FROM Users WHERE PK_USER = ?;"

const qryGetUserEmail = "SELECT Email FROM Users WHERE PK_USER = ?;"

const qryGetUsersCount = "SELECT COUNT(*) FROM Users"

const qryDeleteUser = "DELETE FROM Users WHERE PK_USER = ?;"

const qryDeleteSession = "UPDATE Users SET Session_exp = 0 WHERE PK_USER = ?;"

const qryUpdatePass = "UPDATE Users SET Password = ?, Salt = ? WHERE PK_USER = ?;"

const qryUpdateEmail = "UPDATE Users SET Email = ? WHERE PK_USER = ?;"
