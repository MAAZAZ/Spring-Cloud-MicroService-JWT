package org.glsid.customerservice;

import org.glsid.customerservice.entities.Customer;
import org.glsid.customerservice.repository.CustomerRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Bean;
import org.springframework.data.rest.core.config.RepositoryRestConfiguration;
import org.springframework.data.rest.webmvc.RestControllerConfiguration;

@SpringBootApplication
public class CustomerServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(CustomerServiceApplication.class, args);
    }

    @Bean
    CommandLineRunner start(CustomerRepository customerRepository, RepositoryRestConfiguration repositoryRestConfiguration){
        repositoryRestConfiguration.exposeIdsFor(Customer.class);
        return args -> {
            customerRepository.save(new Customer(null,"zakaria maazaz","maazaz.zakaria@gmail.com"));
            customerRepository.save(new Customer(null,"walid maazaz","maazaz.walid@gmail.com"));
            customerRepository.save(new Customer(null,"youssef maazaz","maazaz.youssef@gmail.com"));
            customerRepository.findAll().forEach(System.out::println);
        };
    }
}
