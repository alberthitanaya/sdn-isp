DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS customers;

create table users (
	subscriber_id integer unique not null,
	customer_id integer,
	primary key (subscriber_id)
	FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
);

create table customers (
    customer_id integer unique not null,
    switch_id varchar(30),
	port varchar(3),
    primary key (customer_id)
);

create table smp (
	id integer unique not null,
    username varchar(32),
    password_hash varchar(64),
    primary key (id)
);

INSERT INTO customers VALUES (1,'00:00:b0:48:7a:db:46:04','3');
INSERT INTO customers VALUES (2, '00:00:f8:d1:11:39:4a:76', '3');
