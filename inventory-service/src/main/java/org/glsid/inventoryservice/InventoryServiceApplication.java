package org.glsid.inventoryservice;

import org.glsid.inventoryservice.entities.Product;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.glsid.inventoryservice.repository.ProductRepository;
import org.springframework.data.rest.core.config.RepositoryRestConfiguration;

@SpringBootApplication
public class InventoryServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(InventoryServiceApplication.class, args);
    }

    @Bean
    CommandLineRunner start(ProductRepository productRepository, RepositoryRestConfiguration repositoryRestConfiguration){
        repositoryRestConfiguration.exposeIdsFor(Product.class);
        return args -> {
            productRepository.save(new Product(null,"Iphone 13",10000,12));
            productRepository.save(new Product(null,"HP LaserJet 500",4000,24));
            productRepository.save(new Product(null,"Samsung 8",6000,5));
            productRepository.findAll().forEach(System.out::println);
        };
    }
}
