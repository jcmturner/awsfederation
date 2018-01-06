package database

const (
	DBCreateSchemaAppUser = `CREATE SCHEMA IF NOT EXISTS awsfederation DEFAULT CHARACTER SET utf8;
CREATE USER '%s'@'%%' IDENTIFIED BY '%s';
GRANT ALL ON awsfederation.* TO '%s';
FLUSH PRIVILEGES;`

	DBCreateTables = `SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='TRADITIONAL,ALLOW_INVALID_DATES';

USE awsfederation ;

-- -----------------------------------------------------
-- Table awsfederation.federationUser
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS awsfederation.federationUser (
  arn VARCHAR(128) NOT NULL,
  name VARCHAR(45) NOT NULL,
  ttl INT NOT NULL,
  PRIMARY KEY (arn))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table awsfederation.accountClass
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS awsfederation.accountClass (
  id INT NOT NULL AUTO_INCREMENT,
  class VARCHAR(45) NOT NULL,
  PRIMARY KEY (id),
  UNIQUE INDEX class_UNIQUE (class ASC))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table awsfederation.accountType
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS awsfederation.accountType (
  id INT NOT NULL,
  type VARCHAR(45) NOT NULL,
  class_id INT NOT NULL,
  PRIMARY KEY (id),
  INDEX fk_accountType_accountClass1_idx (class_id ASC),
  CONSTRAINT fk_accountType_accountClass1
    FOREIGN KEY (class_id)
    REFERENCES awsfederation.accountClass (id)
    ON DELETE RESTRICT
    ON UPDATE RESTRICT)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table awsfederation.accountStatus
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS awsfederation.accountStatus (
  id INT NOT NULL AUTO_INCREMENT,
  status VARCHAR(45) NOT NULL,
  PRIMARY KEY (id),
  UNIQUE INDEX status_UNIQUE (status ASC))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table awsfederation.account
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS awsfederation.account (
  id VARCHAR(12) NOT NULL,
  email VARCHAR(128) NOT NULL,
  name VARCHAR(128) NOT NULL,
  accountType_id INT NOT NULL,
  accountStatus_id INT NOT NULL,
  federationUser_arn VARCHAR(128) NOT NULL,
  PRIMARY KEY (id),
  INDEX fk_account_accountType1_idx (accountType_id ASC),
  INDEX fk_account_accountStatus1_idx (accountStatus_id ASC),
  INDEX fk_account_federationUser1_idx (federationUser_arn ASC),
  CONSTRAINT fk_account_accountType1
    FOREIGN KEY (accountType_id)
    REFERENCES awsfederation.accountType (id)
    ON DELETE RESTRICT
    ON UPDATE RESTRICT,
  CONSTRAINT fk_account_accountStatus1
    FOREIGN KEY (accountStatus_id)
    REFERENCES awsfederation.accountStatus (id)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT fk_account_federationUser1
    FOREIGN KEY (federationUser_arn)
    REFERENCES awsfederation.federationUser (arn)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table awsfederation.roleMapping
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS awsfederation.roleMapping (
  id VARCHAR(36) NOT NULL,
  account_id VARCHAR(45) NOT NULL,
  role_arn VARCHAR(128) NOT NULL,
  authz_attrib VARCHAR(128) NOT NULL,
  policy VARCHAR(2048) NULL,
  duration INT NULL,
  session_name_format VARCHAR(256) NULL,
  PRIMARY KEY (id),
  UNIQUE INDEX id_UNIQUE (id ASC),
  INDEX fk_roleMapping_account1_idx (account_id ASC),
  CONSTRAINT fk_roleMapping_account1
    FOREIGN KEY (account_id)
    REFERENCES awsfederation.account (id)
    ON DELETE RESTRICT
    ON UPDATE RESTRICT)
ENGINE = InnoDB;

-- -----------------------------------------------------
-- Table awsfederation.metadata
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS awsfederation.metadata (
  datetime DATETIME NOT NULL,
  version VARCHAR(45) NOT NULL,
  buildhash VARCHAR(40) NOT NULL,
  buildtime DATETIME NOT NULL)
ENGINE = InnoDB;


SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;`
)
