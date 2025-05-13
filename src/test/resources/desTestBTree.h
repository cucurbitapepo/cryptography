#ifndef MATH_PRACTICE_AND_OPERATING_SYSTEMS_TEMPLATE_REPO_B_TREE_H
#define MATH_PRACTICE_AND_OPERATING_SYSTEMS_TEMPLATE_REPO_B_TREE_H

#include <search_tree.h>
#include <logger_guardant.h>

template<
    typename tkey,
    typename tvalue>
class b_tree final:
    public search_tree<tkey, tvalue>
{

private:

    typename b_tree<tkey, tvalue>::common_node *_root;

    size_t _t;

public:

    class infix_iterator final
    {

    private:

        std::stack<std::pair<typename b_tree<tkey, tvalue>::common_node *, int>> _path;

    public:

    explicit infix_iterator(typename search_tree<tkey, tvalue>::common_node *subtree_root);

    public:

        bool operator==(
            infix_iterator const &other) const noexcept;

        bool operator!=(
            infix_iterator const &other) const noexcept;

        infix_iterator &operator++();

        infix_iterator operator++(
            int not_used);

        std::tuple<size_t, size_t, tkey const &, tvalue &> operator*() const;

    };

    class infix_const_iterator final
    {

    private:

        std::stack<std::pair<typename b_tree<tkey, tvalue>::common_node *, int>> _path;

    public:

        explicit infix_const_iterator(typename search_tree<tkey, tvalue>::common_node *subtree_root);

    public:

        bool operator==(
            infix_const_iterator const &other) const noexcept;

        bool operator!=(
            infix_const_iterator const &other) const noexcept;

        infix_const_iterator &operator++();

        infix_const_iterator operator++(
            int not_used);

        std::tuple<size_t, size_t, tkey const &, tvalue const &> operator*() const;

    };

private:

    void insertion(
            typename associative_container<tkey, tvalue>::key_value_pair &&kvp);

public:

    void insert(
        tkey const &key,
        tvalue const &value) override;

    void insert(
        tkey const &key,
        tvalue &&value) override;

    void update(tkey const &key, tvalue const &value);

    void update(tkey const &key, tvalue &&value);

    tvalue &obtain(
        tkey const &key) override;

    tvalue dispose(
        tkey const &key) override;

    std::vector<typename associative_container<tkey, tvalue>::key_value_pair> obtain_between(
        tkey const &lower_bound,
        tkey const &upper_bound,
        bool lower_bound_inclusive,
        bool upper_bound_inclusive) override;

public:

    explicit b_tree(
        size_t t,
        std::function<int(tkey const &, tkey const &)> keys_comparer = std::less<tkey>(),
        allocator *allocator = nullptr,
        logger *logger = nullptr);

    b_tree(
        b_tree<tkey, tvalue> const &other);

    b_tree<tkey, tvalue> &operator=(
        b_tree<tkey, tvalue> const &other);

    b_tree(
        b_tree<tkey, tvalue> &&other) noexcept;

    b_tree<tkey, tvalue> &operator=(
        b_tree<tkey, tvalue> &&other) noexcept;

    ~b_tree();

public:

    infix_iterator begin_infix() const noexcept;

    infix_iterator end_infix() const noexcept;

    infix_const_iterator cbegin_infix() const noexcept;

    infix_const_iterator cend_infix() const noexcept;

private:

    typename b_tree<tkey, tvalue>::common_node *copy(
            typename b_tree<tkey, tvalue>::common_node *node);

    typename b_tree<tkey, tvalue>::common_node *copy();

    void clear(
            typename b_tree<tkey, tvalue>::common_node *node);

    void clear();

protected:

    std::stack<std::pair<typename b_tree<tkey, tvalue>::common_node **, int>> find_path(
        tkey const &key);

    int node_find_path(
        typename b_tree<tkey, tvalue>::common_node const *node,
        tkey const &key,
        size_t left_bound_inclusive,
        size_t right_bound_inclusive);

    void node_insert(
        typename b_tree<tkey, tvalue>::common_node *node,
        typename associative_container<tkey, tvalue>::key_value_pair &&kvp,
        size_t subtree_index,
        typename b_tree<tkey, tvalue>::common_node *right_subtree);

    std::pair<typename b_tree<tkey, tvalue>::common_node *, typename associative_container<tkey, tvalue>::key_value_pair> node_split(
        typename b_tree<tkey, tvalue>::common_node *node,
        typename associative_container<tkey, tvalue>::key_value_pair &&kvp,
        size_t subtree_index,
        typename b_tree<tkey, tvalue>::common_node *right_subtree);

    void merge_nodes(
        typename b_tree<tkey, tvalue>::common_node *parent,
        int left_subtree_index);

    inline size_t max_keys_count() const noexcept;

    inline size_t min_keys_count() const noexcept;
};


template<
        typename tkey,
        typename tvalue>
std::stack<std::pair<typename b_tree<tkey, tvalue>::common_node **, int>> b_tree<tkey, tvalue>::find_path(
        tkey const &key)
{
    std::stack<std::pair<typename b_tree<tkey, tvalue>::common_node **, int>> result;

    int index = -1;
    if (_root == nullptr)
    {
        result.push(std::pair<typename b_tree<tkey, tvalue>::common_node **, int>(&_root, index));

        return result;
    }

    typename b_tree<tkey, tvalue>::common_node **iterator = &_root;
    while (*iterator != nullptr && index < 0)
    {
        index = b_tree<tkey, tvalue>::node_find_path(*iterator, key, 0, (*iterator)->virtual_size - 1);

        result.push(std::pair<typename b_tree<tkey, tvalue>::common_node **, int>(iterator, index));

        if (index < 0)
        {
            iterator = (*iterator)->subtrees - index - 1;
        }
    }

    return result;
}


template<
        typename tkey,
        typename tvalue>
int b_tree<tkey, tvalue>::node_find_path(
        typename b_tree<tkey, tvalue>::common_node const *node,
        tkey const &key,
        size_t left_bound_inclusive,
        size_t right_bound_inclusive)
{
    int index;

    while (true)
    {
        index = (left_bound_inclusive + right_bound_inclusive) / 2;
        auto comparison_result = search_tree<tkey, tvalue>::_keys_comparer(key, node->keys_and_values[index].key);
        if (comparison_result == 0)
        {
            return index;
        }

        if (left_bound_inclusive == right_bound_inclusive)
        {
            return -(index + (comparison_result < 0
                              ? 0
                              : 1) + 1);
        }

        if (comparison_result < 0)
        {
            right_bound_inclusive = index;
        }
        else
        {
            left_bound_inclusive = index + 1;
        }
    }
}

template<
        typename tkey,
        typename tvalue>
void b_tree<tkey, tvalue>::node_insert(
        typename b_tree<tkey, tvalue>::common_node *node,
        typename associative_container<tkey, tvalue>::key_value_pair &&kvp,
        size_t subtree_index,
        typename b_tree<tkey, tvalue>::common_node *right_subtree)
{
    allocator::construct(node->keys_and_values + node->virtual_size, std::move(kvp));
    node->subtrees[node->virtual_size + 1] = right_subtree;

    for (auto i = 0; i < node->virtual_size - subtree_index; i++)
    {
        search_tree<tkey, tvalue>::swap(std::move(node->keys_and_values[node->virtual_size - i]),
             std::move(node->keys_and_values[node->virtual_size - i - 1]));
        search_tree<tkey, tvalue>::swap(std::move(node->subtrees[node->virtual_size + 1 - i]), std::move(node->subtrees[node->virtual_size - i]));
    }

    ++node->virtual_size;
}


template<
        typename tkey,
        typename tvalue>
std::pair<typename b_tree<tkey, tvalue>::common_node *, typename associative_container<tkey, tvalue>::key_value_pair>
b_tree<tkey, tvalue>::node_split(
        typename b_tree<tkey, tvalue>::common_node *node,
        typename associative_container<tkey, tvalue>::key_value_pair &&kvp,
        size_t subtree_index,
        typename b_tree<tkey, tvalue>::common_node *right_subtree)
{
    size_t median_index = node->virtual_size / 2;

    typename b_tree<tkey, tvalue>::common_node *new_node = b_tree<tkey, tvalue>::create_node(_t);
    new_node->virtual_size = node->virtual_size - median_index - 1;

    for (size_t i = 0; i < new_node->virtual_size; ++i)
    {
        allocator::construct(new_node->keys_and_values + i, std::move(node->keys_and_values[median_index + i + 1]));
        new_node->subtrees[i] = node->subtrees[median_index + 1 + i];
    }
    new_node->subtrees[new_node->virtual_size] = node->subtrees[node->virtual_size];

    node->virtual_size = median_index;

    if (subtree_index > median_index)
    {
        this->node_insert(new_node, std::move(kvp), subtree_index - median_index - 1, right_subtree);
    }
    else
    {//here is kostyl, a che
        ++node->virtual_size;
        this->node_insert(node, std::move(kvp), subtree_index, right_subtree);
        --node->virtual_size;
    }

    return std::make_pair(new_node, std::move(node->keys_and_values[node->virtual_size]));
}

template<
        typename tkey,
        typename tvalue>
void b_tree<tkey, tvalue>::merge_nodes(
        typename b_tree<tkey, tvalue>::common_node *parent,
        int left_subtree_index)
{
    if(left_subtree_index < 0 || left_subtree_index >= parent->virtual_size)
    {
        throw std::logic_error("wrong arguments");
    }
    auto *left_subtree = parent->subtrees[left_subtree_index];
    auto *right_subtree = parent->subtrees[left_subtree_index + 1];

    allocator::construct(left_subtree->keys_and_values + left_subtree->virtual_size++, std::move(parent->keys_and_values[left_subtree_index]));
    for (auto i = left_subtree_index; i < parent->virtual_size - 1; ++i)
    {
        search_tree<tkey, tvalue>::swap(std::move(parent->keys_and_values[i]), std::move(parent->keys_and_values[i + 1]));

        search_tree<tkey, tvalue>::swap(std::move(parent->subtrees[i + 1]), std::move(parent->subtrees[i + 2]));
    }

    allocator::destruct(parent->keys_and_values + --parent->virtual_size);

    for (auto i = 0; i < right_subtree->virtual_size; i++)
    {
        allocator::construct(left_subtree->keys_and_values + left_subtree->virtual_size, std::move(right_subtree->keys_and_values[i]));
        left_subtree->subtrees[left_subtree->virtual_size++] = right_subtree->subtrees[i];
    }
    left_subtree->subtrees[left_subtree->virtual_size] = right_subtree->subtrees[right_subtree->virtual_size];

    b_tree<tkey, tvalue>::destroy_node(right_subtree);
}

template<
        typename tkey,
        typename tvalue>
inline size_t b_tree<tkey, tvalue>::max_keys_count() const noexcept
{
    return 2 * _t - 1;
}

template<
        typename tkey,
        typename tvalue>
inline size_t b_tree<tkey, tvalue>::min_keys_count() const noexcept
{
    return _t - 1;
}

template<
        typename tkey,
        typename tvalue>
typename b_tree<tkey, tvalue>::common_node *b_tree<tkey, tvalue>::copy(
        typename b_tree<tkey, tvalue>::common_node *node)
{
    if (node == nullptr)
    {
        return nullptr;
    }

    typename b_tree<tkey, tvalue>::common_node *copied = b_tree<tkey, tvalue>::create_node(_t);
    copied->virtual_size = node->virtual_size;

    for (size_t i = 0; i < node->virtual_size; ++i)
    {
        allocator::construct(copied->keys_and_values + i, node->keys_and_values[i]);
    }

    for (size_t i = 0; i <= node->virtual_size; ++i)
    {
        copied->subtrees[i] = copy(node->subtrees[i]);
    }

    return copied;
}

template<
        typename tkey,
        typename tvalue>
typename b_tree<tkey, tvalue>::common_node *b_tree<tkey, tvalue>::copy()
{
    return copy(this->_root);
}

template<
        typename tkey,
        typename tvalue>
void b_tree<tkey, tvalue>::clear(
        typename b_tree<tkey, tvalue>::common_node *node)
{
    if (node == nullptr)
    {
        return;
    }

    for (size_t i = 0; i <= node->virtual_size; ++i)
    {
        clear(node->subtrees[i]);
    }

    b_tree<tkey, tvalue>::destroy_node(node);
}

template<
        typename tkey,
        typename tvalue>
void b_tree<tkey, tvalue>::clear()
{
    clear(this->_root);
}

template<
        typename tkey,
        typename tvalue>
b_tree<tkey, tvalue>::infix_iterator::infix_iterator(
        typename search_tree<tkey, tvalue>::common_node *subtree_root)
{
    if(subtree_root != nullptr)
    {
        while(subtree_root != nullptr && subtree_root->virtual_size > 0)
        {
            _path.push(std::make_pair(subtree_root, 0));
            subtree_root = subtree_root->subtrees[0];
        }
    }
}

template<
    typename tkey,
    typename tvalue>
bool b_tree<tkey, tvalue>::infix_iterator::operator==(
    typename b_tree::infix_iterator const &other) const noexcept
{
    if(this->_path.empty() && other._path.empty())
    {
        return true;
    }
    if(this->_path.empty() ^ other._path.empty())
    {
        return false;
    }

    return this->_path.top() == other._path.top();
}

template<
    typename tkey,
    typename tvalue>
bool b_tree<tkey, tvalue>::infix_iterator::operator!=(
    typename b_tree::infix_iterator const &other) const noexcept
{
    return !(*this == other);
}

template<
    typename tkey,
    typename tvalue>
typename b_tree<tkey, tvalue>::infix_iterator &b_tree<tkey, tvalue>::infix_iterator::operator++()
{
    if(_path.empty())
    {
        throw std::logic_error("incrementing empty iterator");
    }

    auto *node = _path.top().first;
    auto index = _path.top().second;

    if(node->subtrees[0] != nullptr)
    {
        index = ++_path.top().second;
        while(node->subtrees[index] != nullptr)
        {
            node = node->subtrees[index];
            index = 0;
            _path.push(std::make_pair(node, 0));
        }

        return *this;
    }

    if(index != node->virtual_size - 1)
    {
        ++_path.top().second;
        return *this;
    }

    do
    {
        _path.pop();
        if(!_path.empty())
        {
            node = _path.top().first;
            index = _path.top().second;
        }
    }
    while(!_path.empty() && index == node->virtual_size - (node->subtrees[0] == nullptr ? 1 : 0));

    return *this;
}

template<
    typename tkey,
    typename tvalue>
typename b_tree<tkey, tvalue>::infix_iterator b_tree<tkey, tvalue>::infix_iterator::operator++(
    int not_used)
{
    auto it = *this;
    ++(*this);
    return it;
}

template<
    typename tkey,
    typename tvalue>
std::tuple<size_t, size_t, tkey const &, tvalue &> b_tree<tkey, tvalue>::infix_iterator::operator*() const
{
    auto &key_value_pair = _path.top().first->keys_and_values[_path.top().second];

    return std::tuple<size_t, size_t, tkey const &, tvalue &>(_path.size() - 1, _path.top().second, key_value_pair.key, key_value_pair.value);
}

template<
        typename tkey,
        typename tvalue>
b_tree<tkey, tvalue>::infix_const_iterator::infix_const_iterator(
    typename search_tree<tkey, tvalue>::common_node *subtree_root)
{
    if(subtree_root != nullptr)
    {
        while(subtree_root != nullptr && subtree_root->virtual_size > 0)
        {
            _path.push(std::make_pair(subtree_root, 0));
            subtree_root = subtree_root->subtrees[0];
        }
    }
}

template<
    typename tkey,
    typename tvalue>
bool b_tree<tkey, tvalue>::infix_const_iterator::operator==(
    b_tree::infix_const_iterator const &other) const noexcept
{
    if(this->_path.empty() && other._path.empty())
    {
        return true;
    }
    if(this->_path.empty() ^ other._path.empty())
    {
        return false;
    }

    return this->_path.top() == other._path.top();
}

template<
    typename tkey,
    typename tvalue>
bool b_tree<tkey, tvalue>::infix_const_iterator::operator!=(
    b_tree::infix_const_iterator const &other) const noexcept
{
    return !(*this == other);
}

template<
    typename tkey,
    typename tvalue>
typename b_tree<tkey, tvalue>::infix_const_iterator &b_tree<tkey, tvalue>::infix_const_iterator::operator++()
{
    if(_path.empty())
    {
        throw std::logic_error("incrementing empty iterator");
    }

    auto *node = _path.top().first;
    auto index = _path.top().second;

    if(node->subtrees[0] != nullptr)
    {
        index = ++_path.top().second;
        while(node->subtrees[index] != nullptr)
        {
            node = node->subtrees[index];
            index = 0;
            _path.push(std::make_pair(node, 0));
        }

        return *this;
    }

    if(index != node->virtual_size - 1)
    {
        ++_path.top().second;
        return *this;
    }

    do
    {
        _path.pop();
        if(!_path.empty())
        {
            node = _path.top().first;
            index = _path.top().second;
        }
    }
    while(!_path.empty() && index == node->virtual_size - (node->subtrees[0] == nullptr ? 1 : 0));

    return *this;
}

template<
    typename tkey,
    typename tvalue>
typename b_tree<tkey, tvalue>::infix_const_iterator b_tree<tkey, tvalue>::infix_const_iterator::operator++(
    int not_used)
{
    auto it = *this;
    ++(*this);
    return it;
}

template<
    typename tkey,
    typename tvalue>
std::tuple<size_t, size_t, tkey const &, tvalue const &> b_tree<tkey, tvalue>::infix_const_iterator::operator*() const
{
    auto &key_value_pair = _path.top().first->keys_and_values[_path.top().second];

    return std::tuple<size_t, size_t, tkey const &, tvalue &>(_path.size() - 1, _path.top().second, key_value_pair.key, key_value_pair.value);
}

template<
        typename tkey,
        typename tvalue>
void b_tree<tkey, tvalue>::insertion(
        typename associative_container<tkey, tvalue>::key_value_pair &&kvp)
{
    auto path = this->find_path(kvp.key);
    auto *node_ptr = path.top().first;

    if (*node_ptr == nullptr && path.size() == 1)
    {
        typename b_tree<tkey, tvalue>::common_node *new_node = b_tree<tkey, tvalue>::create_node(_t);
        *node_ptr = new_node;
        allocator::construct(new_node->keys_and_values, std::move(kvp));
        ++new_node->virtual_size;
        return;
    }

    if (path.top().second >= 0)
    {
        throw std::logic_error("duplicate key");
    }

    size_t subtree_index = -path.top().second - 1;
    typename b_tree<tkey, tvalue>::common_node *right_subtree = nullptr;

    while (true)
    {
        auto *node = *node_ptr;

        if (node->virtual_size < max_keys_count() - 1)
        {
            this->node_insert(node, std::move(kvp), subtree_index, right_subtree);
            return;
        }

        auto res = this->node_split(node, std::move(kvp), subtree_index, right_subtree);
        right_subtree = res.first;
        kvp = std::move(res.second);

        if (path.size() == 1)
        {
            typename b_tree<tkey, tvalue>::common_node *new_root = b_tree<tkey, tvalue>::create_node(_t);
            new_root->virtual_size = 1;
            allocator::construct(new_root->keys_and_values, std::move(kvp));
            new_root->subtrees[0] = node;
            new_root->subtrees[1] = right_subtree;
            *node_ptr = new_root;
            return;
        }

        path.pop();
        node_ptr = path.top().first;
        subtree_index = -path.top().second - 1;


    }
}

template<
    typename tkey,
    typename tvalue>
void b_tree<tkey, tvalue>::insert(
    tkey const &key,
    tvalue const &value)
{
    insertion(std::move(typename associative_container<tkey, tvalue>::key_value_pair(key, value)));
}

template<
    typename tkey,
    typename tvalue>
void b_tree<tkey, tvalue>::insert(
    tkey const &key,
    tvalue &&value)
{
    try
    {
        insertion(std::move(typename associative_container<tkey, tvalue>::key_value_pair(key, std::move(value))));
    }
    catch(...)
    {
        throw;
    }
}

template<
        typename tkey,
        typename tvalue>
void b_tree<tkey, tvalue>::update(
        tkey const &key,
        tvalue const &value)
{
    auto path = this->find_path(key);
    if(path.top().second < 0)
    {
        logger_guardant::warning_with_guard("key for update was not found");
    }

    (*path.top().first)->keys_and_values[path.top().second].value = value;
}

template<
        typename tkey,
        typename tvalue>
void b_tree<tkey, tvalue>::update(
        tkey const &key,
        tvalue &&value)
{
    auto path = this->find_path(key);
    if(path.top().second < 0)
    {
        logger_guardant::warning_with_guard("key for update was not found");
    }

    (*path.top().first)->keys_and_values[path.top().second].value = std::move(value);
}

template<
    typename tkey,
    typename tvalue>
tvalue &b_tree<tkey, tvalue>::obtain(
    tkey const &key)
{
    auto path = this->find_path(key);
    if (path.top().second < 0)
    {
        throw std::logic_error("key not found");
    }

    return (*path.top().first)->keys_and_values[path.top().second].value;
}

template<
    typename tkey,
    typename tvalue>
tvalue b_tree<tkey, tvalue>::dispose(
    tkey const &key)
{
    auto path = this->find_path(key);
    if (path.top().second < 0)
    {
        throw std::logic_error("key not found");
    }

    if ((*path.top().first)->subtrees[0] != nullptr)
    {
        auto non_terminal_node_with_key_found_info = path.top();
        path.pop();
        typename b_tree<tkey, tvalue>::common_node **iterator = non_terminal_node_with_key_found_info.first;

        while (*iterator != nullptr)
        {
            auto index = *iterator == *non_terminal_node_with_key_found_info.first
                         ? non_terminal_node_with_key_found_info.second
                         : (*iterator)->virtual_size;

            path.push(std::make_pair(iterator, -index - 1));

            iterator = (*iterator)->subtrees + index;
        }

        search_tree<tkey, tvalue>::swap(std::move(
                                                (*non_terminal_node_with_key_found_info.first)->keys_and_values[non_terminal_node_with_key_found_info.second]),
                                        std::move(
                                                (*path.top().first)->keys_and_values[(*path.top().first)->virtual_size -
                                                                                     1]));
        path.top().second = -path.top().second - 2;
    }

    auto target_node = *path.top().first;
    auto kvp_to_dispose_index = path.top().second;
    path.pop();

    for (size_t i = kvp_to_dispose_index + 1; i < target_node->virtual_size; i++)
    {
        search_tree<tkey, tvalue>::swap(std::move(target_node->keys_and_values[i - 1]),
                                        std::move(target_node->keys_and_values[i]));
    }

    tvalue value = std::move(target_node->keys_and_values[--target_node->virtual_size].value);

    allocator::destruct(target_node->keys_and_values + target_node->virtual_size);


    while (true)
    {
        if (target_node->virtual_size >= min_keys_count())
        {
            return value;
        }

        if (path.size() == 0)
        {
            if (target_node->virtual_size == 0)
            {
                this->_root = target_node->subtrees[0];
                b_tree<tkey, tvalue>::destroy_node(target_node);
            }

            return value;
        }

        typename b_tree<tkey, tvalue>::common_node *parent = *path.top().first;
        size_t position = -path.top().second - 1;
        path.pop();

        bool const left_brother_exists = position != 0;
        bool const can_take_from_left_brother =
                left_brother_exists &&
                parent->subtrees[position - 1]->virtual_size > min_keys_count();

        bool const right_brother_exists = position != parent->virtual_size;
        bool const can_take_from_right_brother =
                right_brother_exists &&
                parent->subtrees[position + 1]->virtual_size > min_keys_count();

        if (can_take_from_left_brother)
        {
            auto *left_brother = parent->subtrees[position - 1];
            search_tree<tkey, tvalue>::swap(std::move(parent->keys_and_values[position - 1]),
                                            std::move(left_brother->keys_and_values[left_brother->virtual_size - 1]));

            allocator::construct(target_node->keys_and_values + target_node->virtual_size,
                                 std::move(left_brother->keys_and_values[left_brother->virtual_size - 1]));
            search_tree<tkey, tvalue>::swap(std::move(left_brother->subtrees[left_brother->virtual_size]),
                                            std::move(target_node->subtrees[target_node->virtual_size]));
            target_node->subtrees[++target_node->virtual_size] = left_brother->subtrees[left_brother->virtual_size];

            for (auto i = target_node->virtual_size - 1; i > 0; --i)
            {
               search_tree<tkey, tvalue>::swap(std::move(target_node->keys_and_values[i]),
                                                std::move(target_node->keys_and_values[i - 1]));

               search_tree<tkey, tvalue>::swap(std::move(target_node->subtrees[i + 1]),
                                                std::move(target_node->subtrees[i]));
            }

            allocator::destruct(left_brother->keys_and_values + --left_brother->virtual_size);

            return value;
        }

        if (can_take_from_right_brother)
        {
            auto *right_brother = parent->subtrees[position + 1];
            search_tree<tkey, tvalue>::swap(std::move(parent->keys_and_values[position]),
                                            std::move(right_brother->keys_and_values[0]));

            allocator::construct(target_node->keys_and_values + target_node->virtual_size,
                                 std::move(right_brother->keys_and_values[0]));
            target_node->subtrees[++target_node->virtual_size] = right_brother->subtrees[0];

            for (size_t i = 0; i < right_brother->virtual_size - 1; ++i)
            {
                search_tree<tkey, tvalue>::swap(std::move(right_brother->keys_and_values[i]),
                                                std::move(right_brother->keys_and_values[i + 1]));

                search_tree<tkey, tvalue>::swap(std::move(right_brother->subtrees[i]),
                                                std::move(right_brother->subtrees[i + 1]));
            }

            right_brother->subtrees[right_brother->virtual_size -
                                    1] = right_brother->subtrees[right_brother->virtual_size];

            allocator::destruct(right_brother->keys_and_values + --right_brother->virtual_size);

            return value;
        }

        this->merge_nodes(parent, position - (left_brother_exists
                                              ? 1
                                              : 0));

        target_node = parent;
    }
}

template<
    typename tkey,
    typename tvalue>
std::vector<typename associative_container<tkey, tvalue>::key_value_pair> b_tree<tkey, tvalue>::obtain_between(
    tkey const &lower_bound,
    tkey const &upper_bound,
    bool lower_bound_inclusive,
    bool upper_bound_inclusive)
{
    std::vector<typename associative_container<tkey, tvalue>::key_value_pair> range;
    b_tree<tkey, tvalue>::infix_const_iterator it = cbegin_infix();

    while ((it != cend_infix()) &&
           (search_tree<tkey, tvalue>::_keys_comparer(upper_bound, std::get<2>(*it)) > (upper_bound_inclusive ? -1 : 0)))
    {
        if (search_tree<tkey, tvalue>::_keys_comparer(lower_bound, std::get<2>(*it)) < (lower_bound_inclusive ? 1 : 0))
        {
            range.push_back(std::move(
                    typename associative_container<tkey, tvalue>::key_value_pair(std::get<2>(*it), std::get<3>(*it))));
        }
        ++it;
    }

    return range;
}

template<
    typename tkey,
    typename tvalue>
b_tree<tkey, tvalue>::b_tree(
    size_t t,
    std::function<int(tkey const &, tkey const &)> keys_comparer,
    allocator *allocator,
    logger *logger)
    : search_tree<tkey, tvalue>(keys_comparer, logger, allocator)
{
    if ((_t = t) < 2)
    {
        throw std::logic_error("Invalid value of t parameter");
    }
    _root = nullptr;
}

template<
    typename tkey,
    typename tvalue>
b_tree<tkey, tvalue>::b_tree(
    b_tree<tkey, tvalue> const &other)
    : search_tree<tkey, tvalue>(other._keys_comparer, other.get_logger(), other.get_allocator()),
    _t(other._t)
{
    this->_root = copy(other._root);
}

template<
    typename tkey,
    typename tvalue>
b_tree<tkey, tvalue> &b_tree<tkey, tvalue>::operator=(
        b_tree<tkey, tvalue> const &other)
{
    if (this != &other)
    {
        clear();
        this->_logger = other.get_logger();
        this->_allocator = other.get_allocator();
        this->_root = copy(other._root);
    }

    return *this;
}

template<
    typename tkey,
    typename tvalue>
b_tree<tkey, tvalue>::b_tree(
    b_tree<tkey, tvalue> &&other) noexcept
    : search_tree<tkey, tvalue>(other._keys_comparer, other.get_logger(),other.get_allocator()),
     _t(other._t)
{
    this->_root = other._root;
    other._root = nullptr;
    other._logger = nullptr;
    other._allocator = nullptr;
}

template<
    typename tkey,
    typename tvalue>
b_tree<tkey, tvalue> &b_tree<tkey, tvalue>::operator=(
    b_tree<tkey, tvalue> &&other) noexcept
{
    if (this != &other)
    {
        clear();

        search_tree<tkey, tvalue>::_keys_comparer = other._keys_comparer;

        this->_logger = std::move(other._logger);
        other._logger = nullptr;

        this->_allocator = std::move(other._allocator);
        other._allocator = nullptr;

        this->_root = std::move(other._root);
        other._root = nullptr;
    }

    return *this;
}

template<
    typename tkey,
    typename tvalue>
b_tree<tkey, tvalue>::~b_tree()
{
    clear();
}

template<
    typename tkey,
    typename tvalue>
typename b_tree<tkey, tvalue>::infix_iterator b_tree<tkey, tvalue>::begin_infix() const noexcept
{
    return b_tree<tkey, tvalue>::infix_iterator(this->_root);
}

template<
    typename tkey,
    typename tvalue>
typename b_tree<tkey, tvalue>::infix_iterator b_tree<tkey, tvalue>::end_infix() const noexcept
{
    return b_tree<tkey, tvalue>::infix_iterator(nullptr);
}

template<
    typename tkey,
    typename tvalue>
typename b_tree<tkey, tvalue>::infix_const_iterator b_tree<tkey, tvalue>::cbegin_infix() const noexcept
{
    return b_tree<tkey, tvalue>::infix_const_iterator(this->_root);
}

template<
    typename tkey,
    typename tvalue>
typename b_tree<tkey, tvalue>::infix_const_iterator b_tree<tkey, tvalue>::cend_infix() const noexcept
{
    return b_tree<tkey, tvalue>::infix_const_iterator(nullptr);
}

#endif //MATH_PRACTICE_AND_OPERATING_SYSTEMS_TEMPLATE_REPO_B_TREE_H