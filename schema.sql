DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS customers;
DROP TABLE IF EXISTS smp;


create table customers (
    customer_id varchar(30),
    switch_id varchar(30),
    port varchar(3),
    billingDay integer,
    quota integer,
    primary key (customer_id)
);

create table users (
	handle varchar(30),
	customer_id varchar(30),
	primary key (handle),
	FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
);

create table smp (
    id integer,
    username varchar(32),
    password_hash varchar(120),
    primary key (id)
);

INSERT INTO customers VALUES ('john_home','00:00:b0:48:7a:db:46:04','4', 7, 750 );
INSERT INTO customers VALUES ('albert_home', '00:00:f8:d1:11:39:4a:76', '4', 15, 200);
INSERT INTO customers VALUES ('uniwide_sdn', '00:00:a0:36:9f:1e:0c:cf', '3', 30, 1000);

INSERT INTO users VALUES ('albert_1','john_home');
INSERT INTO users VALUES ('albert_2','albert_home');
INSERT INTO users VALUES ('albert_3','uniwide_sdn');
