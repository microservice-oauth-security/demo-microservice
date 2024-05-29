package org.codewithanish.controller;

import org.codewithanish.vo.Employee;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/demo-service/employee")
public class DemoController {


    @GetMapping
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public ResponseEntity<List<Employee>> getEmployees()
    {
        return  new ResponseEntity<>(List.of(
                new Employee("Sundar Pichai","Google", "CEO"),
                new Employee("Elon Musk", "Tesla", "CEO"),
                new Employee("Mark Zuckerberg", "Meta", "CEO"),
                new Employee("Anish", "Code With Anish", "Architect/Developer")

        ), HttpStatus.OK);
    }

}
