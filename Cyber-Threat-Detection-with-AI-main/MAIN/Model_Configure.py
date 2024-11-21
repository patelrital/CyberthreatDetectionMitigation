import tensorflow as tf

def create_dense_layer(
        prev_layer=None,
        units:int=None, 
        activation:str=None,
        regularization_rate:float=0.01
):
    """Creates a dense layer with L2 regularization"""
    return tf.keras.layers.Dense(
        units=units,
        activation=activation,
        kernel_regularizer=tf.keras.regularizers.l2(regularization_rate)  # Improved with regularization
    )(prev_layer)

def create_dropout_layer(
        prev_layer=None,
        dropout_rate:float=0.2
):
    """Creates a dropout layer"""
    return tf.keras.layers.Dropout(dropout_rate)(prev_layer)

def create_model(
        X=None,
        y=None,
        num_layers:int=12,
        epoch:int=100,
        batch_size:int=2,
        validation_split:float=0.2
):
    """
    Creates a neural network model with automatically sized layers based on input dimensions.
    
    Args:
        X: Input features array
        y: Target labels array 
        num_layers: Total number of layers to create
        epoch: Number of training epochs
        batch_size: Training batch size
        validation_split: Validation data fraction
        
    Returns:
        Compiled Keras model
    """
    input_dim = len(X[0])  # Get input dimension
    output_dim = len(y[0])  # Get output dimension

    # Create input layer
    input_layer = tf.keras.layers.Input(shape=(input_dim,))

    # Build hidden layers
    current_layer = input_layer
    layers_per_section = num_layers // 2  # Number of layers in expanding/contracting sections

    # Expanding section
    for i in range(1, layers_per_section + 1):
        if i % 3 == 0:
            current_layer = create_dropout_layer(
                prev_layer=current_layer
            )
        else:
            current_layer = create_dense_layer(
                prev_layer=current_layer,
                units=((input_dim//2)//2) * i,  # Improved with reduced layer sizes
                activation='relu'
            )

    # Contracting section  
    for i in reversed(range(1, layers_per_section + 1)):
        if i % 3 == 0:
            current_layer = create_dropout_layer(
                prev_layer=current_layer
            )
        else:
            current_layer = create_dense_layer(
                prev_layer=current_layer,
                units=((input_dim//2)//2) * i,
                activation='relu'
            )

    # Add final dropout layer
    current_layer = create_dropout_layer(
        prev_layer=current_layer
    )

    # Output layer
    output_layer = tf.keras.layers.Dense(
        output_dim,
        activation='softmax'
    )(current_layer)

    # Create and compile model
    model = tf.keras.models.Model(inputs=input_layer, outputs=output_layer)
    
    # Print model summary
    model.summary()
    
    return model