package com.softserveinc.ch067.easypay.config;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.env.Environment;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.JpaVendorAdapter;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import javax.persistence.EntityManagerFactory;
import javax.sql.DataSource;
import java.util.Objects;
import java.util.Properties;

@PropertySource("database-test.properties")
@Configuration
@EnableTransactionManagement
public class  DatabaseConfigTest {

    @Autowired
    private Environment env;

    @Bean
    public DataSource dataSource() {
        HikariConfig hikariConfig = new HikariConfig();

        hikariConfig.setDriverClassName(env.getProperty("jdbc.driverClassName"));
        hikariConfig.setJdbcUrl(env.getProperty("jdbc.url"));
        hikariConfig.setUsername(env.getProperty("jdbc.user"));
        hikariConfig.setPassword(env.getProperty("jdbc.pass"));

        hikariConfig.addDataSourceProperty("cachePrepStmts", "true");
        hikariConfig.addDataSourceProperty("prepStmtCacheSize", "250");
        hikariConfig.addDataSourceProperty("prepStmtCacheSqlLimit", "2048");

        return new HikariDataSource(hikariConfig);
    }

    @Bean
    @Autowired
    public PlatformTransactionManager getTransactionManager(EntityManagerFactory emf) {
        JpaTransactionManager jpaTransaction = new JpaTransactionManager();
        jpaTransaction.setEntityManagerFactory(emf);
        return jpaTransaction;
    }

    @Bean
    public LocalContainerEntityManagerFactoryBean getEMF() {
        LocalContainerEntityManagerFactoryBean emf = new LocalContainerEntityManagerFactoryBean();
        emf.setDataSource(dataSource());
        emf.setPackagesToScan("com.softserveinc.ch067.easypay.model");
        emf.setJpaVendorAdapter(getHibernateAdapter());
        Properties jpaProperties = new Properties();
        jpaProperties.put("hibernate.dialect", Objects.requireNonNull(env.getProperty("hibernate.dialect")));
        jpaProperties.put("hibernate.hbm2ddl.auto", Objects.requireNonNull(env.getProperty("hibernate.hbm2ddl.auto")));
        jpaProperties.put("hibernate.show_sql", Objects.requireNonNull(env.getProperty("hibernate.show_sql")));
        jpaProperties.put("hibernate.format_sql", Objects.requireNonNull(env.getProperty("hibernate.format_sql")));
        emf.setJpaProperties(jpaProperties);
        return emf;
    }

    @Bean
    public JpaVendorAdapter getHibernateAdapter() {
        return new HibernateJpaVendorAdapter();
    }

}
