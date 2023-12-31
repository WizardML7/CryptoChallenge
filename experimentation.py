def inverse_expression(j, y, d, q, aConstant, bConstant):
    intermediate_result = j ^ ((d[y >> aConstant] * q) ^ (0xface * (y >> aConstant)))
    j_inverse = intermediate_result ^ (0xface * (y >> aConstant)) ^ (d[y >> aConstant] * q)
    return j_inverse

# Example values (replace with actual values):
j_value =  3735889047# Your j value
y_value =  2# Your y value
d_array =  b"D"# Your d array (list or bytes)
q_value = 3405691582 # Your q value
aConstant = 20
    #DEAD BEFB

bConstant = 1048576

# Call the function
result = inverse_expression(j_value, y_value, d_array, q_value, aConstant, bConstant)

# Print the result
print("Inverse j:", result)