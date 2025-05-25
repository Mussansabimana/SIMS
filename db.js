const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');

async function initializeDatabase() {
  try {
    const db = await open({
      filename: './sims.db',
      driver: sqlite3.Database
    });
    
    // Create tables if they don't exist
    await db.exec(`
      CREATE TABLE IF NOT EXISTS Users (
        UsersID INTEGER PRIMARY KEY AUTOINCREMENT,
        Username TEXT UNIQUE NOT NULL,
        Password TEXT NOT NULL,
        Role TEXT DEFAULT 'user',
        LastLogin TIMESTAMP,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      CREATE TABLE IF NOT EXISTS Spare_Part (
        PartID INTEGER PRIMARY KEY AUTOINCREMENT,
        Name TEXT NOT NULL,
        Category TEXT,
        Quantity INTEGER DEFAULT 0,
        UnitPrice REAL DEFAULT 0,
        TotalPrice REAL DEFAULT 0
      );
      
      CREATE TABLE IF NOT EXISTS Stock_In (
        StockInID INTEGER PRIMARY KEY AUTOINCREMENT,
        PartID INTEGER,
        UsersID INTEGER,
        StockInQuantity INTEGER,
        StockInDate TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (PartID) REFERENCES Spare_Part(PartID),
        FOREIGN KEY (UsersID) REFERENCES Users(UsersID)
      );
      
      CREATE TABLE IF NOT EXISTS Stock_Out (
        StockOutID INTEGER PRIMARY KEY AUTOINCREMENT,
        PartID INTEGER,
        UsersID INTEGER,
        StockOutQuantity INTEGER,
        StockOutUnitPrice REAL,
        StockOutTotalPrice REAL,
        StockOutDate TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (PartID) REFERENCES Spare_Part(PartID),
        FOREIGN KEY (UsersID) REFERENCES Users(UsersID)
      );
      
      CREATE TABLE IF NOT EXISTS Report (
        ReportID INTEGER PRIMARY KEY AUTOINCREMENT,
        UsersID INTEGER,
        ReportDate TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        Summary TEXT,
        Details TEXT,
        FOREIGN KEY (UsersID) REFERENCES Users(UsersID)
      );
    `);
    
    return db;
  } catch (err) {
    console.error('Database initialization error:', err);
    throw err;
  }
}

module.exports = initializeDatabase;